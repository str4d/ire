use cookie_factory::*;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use nom::*;
use rand::rngs::OsRng;
use sha2::{
    digest::generic_array::{typenum::U32, GenericArray},
    Digest, Sha256,
};
use std::io::{Read, Write};

use super::*;
use crate::constants::{
    NETDB_STORE_ENC_LS2, NETDB_STORE_LS, NETDB_STORE_LS2, NETDB_STORE_META_LS2, NETDB_STORE_RI,
};
use crate::crypto::frame::{gen_session_key, session_key};
use crate::data::{
    dest::frame::{gen_lease_set, lease_set},
    frame::{
        certificate, gen_certificate, gen_hash, gen_i2p_date, gen_router_info, gen_session_tag,
        gen_short_expiry, gen_tunnel_id, hash, i2p_date, router_info, session_tag, short_expiry,
        tunnel_id,
    },
    ls2::{
        enc::frame::{encrypted_ls2, gen_encrypted_ls2},
        frame::{gen_lease_set_2, gen_meta_ls2, lease_set_2, meta_ls2},
    },
};

//
// Utils
//

fn iv<'a>(input: &'a [u8]) -> IResult<&'a [u8], [u8; 16]> {
    let (i, iv) = take!(input, 16)?;
    let mut x = [0u8; 16];
    x.copy_from_slice(iv);
    Ok((i, x))
}

//
// Common structures
//

named!(
    pub build_request_record<BuildRequestRecord>,
    do_parse!(
        receive_tid: tunnel_id
            >> our_ident: hash
            >> next_tid: tunnel_id
            >> next_ident: hash
            >> layer_key: session_key
            >> iv_key: session_key
            >> reply_key: session_key
            >> reply_iv: iv
            >> hop_type:
                map!(
                    verify!(
                        bits!(do_parse!(
                            ibgw: take_bits!(u8, 1)
                                >> obep: take_bits!(u8, 1)
                                >> take_bits!(u8, 6)
                                >> ((ibgw > 0, obep > 0))
                        )),
                        |(ibgw, obep)| !(ibgw && obep)
                    ),
                    |(ibgw, obep)| match (ibgw, obep) {
                        (false, false) => ParticipantType::Intermediate,
                        (true, false) => ParticipantType::InboundGateway,
                        (false, true) => ParticipantType::OutboundEndpoint,
                        (true, true) => unreachable!(),
                    }
                )
            >> request_time: be_u32
            >> send_msg_id: be_u32
            >> take!(29)
            >> (BuildRequestRecord {
                receive_tid,
                our_ident,
                next_tid,
                next_ident,
                layer_key,
                iv_key,
                reply_key,
                reply_iv,
                hop_type,
                request_time,
                send_msg_id,
            })
    )
);

pub fn gen_build_request_record<'a>(
    input: (&'a mut [u8], usize),
    brr: &BuildRequestRecord,
) -> Result<(&'a mut [u8], usize), GenError> {
    let flags: u8 = match brr.hop_type {
        ParticipantType::Intermediate => 0b0000_0000,
        ParticipantType::InboundGateway => 0b1000_0000,
        ParticipantType::OutboundEndpoint => 0b0100_0000,
    };
    let mut padding = [0; 29];
    let mut rng = OsRng::new().expect("should be able to construct RNG");
    rng.fill(&mut padding[..]);
    do_gen!(
        input,
        gen_tunnel_id(&brr.receive_tid)
            >> gen_hash(&brr.our_ident)
            >> gen_tunnel_id(&brr.next_tid)
            >> gen_hash(&brr.next_ident)
            >> gen_session_key(&brr.layer_key)
            >> gen_session_key(&brr.iv_key)
            >> gen_session_key(&brr.reply_key)
            >> gen_slice!(&brr.reply_iv)
            >> gen_be_u8!(flags)
            >> gen_be_u32!(brr.request_time)
            >> gen_be_u32!(brr.send_msg_id)
            >> gen_slice!(&padding)
    )
}

fn calculate_build_response_record_hash(padding: &[u8], reply: u8) -> GenericArray<u8, U32> {
    let mut hasher = Sha256::default();
    hasher.input(padding);
    hasher.input(&[reply]);
    hasher.result()
}

fn validate_build_response_record<'a>(
    input: &'a [u8],
    hash: &Hash,
    padding: &[u8],
    reply: u8,
) -> IResult<&'a [u8], ()> {
    let res = calculate_build_response_record_hash(padding, reply);
    if hash.eq(&Hash::from_bytes(array_ref![res, 0, 32])) {
        Ok((input, ()))
    } else {
        Err(Err::Error(error_position!(input, ErrorKind::Custom(1))))
    }
}

named!(pub build_response_record<BuildResponseRecord>,
    do_parse!(
        hash:    hash >>
        padding: take!(495) >>
        reply:   be_u8 >>
                 call!(validate_build_response_record, &hash, padding, reply) >>
        (BuildResponseRecord { reply })
    )
);

pub fn gen_build_response_record<'a>(
    input: (&'a mut [u8], usize),
    brr: &BuildResponseRecord,
) -> Result<(&'a mut [u8], usize), GenError> {
    let mut padding = vec![0; 495];
    let mut rng = OsRng::new().expect("should be able to construct RNG");
    rng.fill(&mut padding[..]);
    let hash = calculate_build_response_record_hash(&padding, brr.reply);
    do_gen!(
        input,
        gen_slice!(hash) >> gen_slice!(padding) >> gen_be_u8!(brr.reply)
    )
}

//
// Message payloads
//

// DatabaseStore

fn compressed_ri<'a>(input: &'a [u8]) -> IResult<&'a [u8], RouterInfo> {
    let (i, payload) = do_parse!(input, size: be_u16 >> payload: take!(size) >> (payload))?;
    let mut buf = Vec::new();
    let mut d = GzDecoder::new(payload);
    match d.read_to_end(&mut buf) {
        Ok(_) => match router_info(&buf) {
            Ok((_, ri)) => Ok((i, ri)),
            Err(Err::Incomplete(n)) => Err(Err::Incomplete(n)),
            Err(Err::Error(c)) => Err(Err::Error(Context::Code(input, c.into_error_kind()))),
            Err(Err::Failure(c)) => Err(Err::Failure(Context::Code(input, c.into_error_kind()))),
        },
        Err(_) => Err(Err::Error(error_position!(input, ErrorKind::Custom(1)))),
    }
}

fn gen_compressed_ri<'a>(
    input: (&'a mut [u8], usize),
    ri: &RouterInfo,
) -> Result<(&'a mut [u8], usize), GenError> {
    let mut buf = Vec::new();
    gen_router_info((&mut buf, 0), ri)?;
    let mut e = GzEncoder::new(Vec::new(), Compression::best());
    match e.write(&buf) {
        Ok(n) if n < buf.len() => Err(GenError::CustomError(1)),
        Ok(_) => match e.finish() {
            Ok(payload) => do_gen!(input, gen_be_u16!(payload.len()) >> gen_slice!(payload)),
            Err(_) => Err(GenError::CustomError(1)),
        },
        Err(_) => Err(GenError::CustomError(1)),
    }
}

#[cfg_attr(rustfmt, rustfmt_skip)]
named!(
    reply_path<Option<ReplyPath>>,
    do_parse!(
        reply_tok: be_u32 >>
        reply: cond!(
            reply_tok > 0,
            do_parse!(
                reply_tid: tunnel_id >>
                reply_gw:  hash >>
                (ReplyPath {
                    token: reply_tok,
                    tid: reply_tid,
                    gateway: reply_gw,
                })
            )
        ) >>
        (reply)
    )
);

fn gen_reply_path<'a>(
    input: (&'a mut [u8], usize),
    reply: &Option<ReplyPath>,
) -> Result<(&'a mut [u8], usize), GenError> {
    match *reply {
        Some(ref path) => do_gen!(
            input,
            gen_be_u32!(path.token) >> gen_tunnel_id(&path.tid) >> gen_hash(&path.gateway)
        ),
        None => gen_be_u32!(input, 0),
    }
}

named!(
    database_store<MessagePayload>,
    do_parse!(
        key: hash
            >> ds_type: be_u8
            >> reply: reply_path
            >> data: switch!(value!(ds_type),
                NETDB_STORE_RI => do_parse!(ri: compressed_ri >> (DatabaseStoreData::RI(ri))) |
                NETDB_STORE_LS => do_parse!(ls: lease_set >> (DatabaseStoreData::LS(ls))) |
                NETDB_STORE_LS2 => do_parse!(ls2: lease_set_2 >> (DatabaseStoreData::LS2(ls2))) |
                NETDB_STORE_ENC_LS2 => do_parse!(enc_ls2: encrypted_ls2 >> (DatabaseStoreData::EncLS2(enc_ls2))) |
                NETDB_STORE_META_LS2 => do_parse!(meta_ls2: meta_ls2 >> (DatabaseStoreData::MetaLS2(meta_ls2)))
            )
            >> (MessagePayload::DatabaseStore(DatabaseStore {
                key,
                ds_type,
                reply,
                data,
            }))
    )
);

fn gen_database_store_data<'a>(
    input: (&'a mut [u8], usize),
    data: &DatabaseStoreData,
) -> Result<(&'a mut [u8], usize), GenError> {
    match *data {
        DatabaseStoreData::RI(ref ri) => gen_compressed_ri(input, &ri),
        DatabaseStoreData::LS(ref ls) => gen_lease_set(input, &ls),
        DatabaseStoreData::LS2(ref ls2) => gen_lease_set_2(input, &ls2),
        DatabaseStoreData::EncLS2(ref enc_ls2) => gen_encrypted_ls2(input, &enc_ls2),
        DatabaseStoreData::MetaLS2(ref meta_ls2) => gen_meta_ls2(input, &meta_ls2),
    }
}

fn gen_database_store<'a>(
    input: (&'a mut [u8], usize),
    ds: &DatabaseStore,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(
        input,
        gen_hash(&ds.key)
            >> gen_be_u8!(ds.ds_type)
            >> gen_reply_path(&ds.reply)
            >> gen_database_store_data(&ds.data)
    )
}

// DatabaseLookup

#[cfg_attr(rustfmt, rustfmt_skip)]
named!(
    database_lookup_flags<DatabaseLookupFlags>,
    bits!(do_parse!(
                     take_bits!(u8, 4) >>
        lookup_type: take_bits!(u8, 2) >>
        encryption:  take_bits!(u8, 1) >>
        delivery:    take_bits!(u8, 1) >>
        (DatabaseLookupFlags {
            delivery: delivery > 0,
            encryption: encryption > 0,
            lookup_type: match lookup_type {
                0 => DatabaseLookupType::Any,
                1 => DatabaseLookupType::LeaseSet,
                2 => DatabaseLookupType::RouterInfo,
                3 => DatabaseLookupType::Exploratory,
                _ => unreachable!(),
            },
        })
    ))
);

fn gen_database_lookup_flags<'a>(
    input: (&'a mut [u8], usize),
    flags: &DatabaseLookupFlags,
) -> Result<(&'a mut [u8], usize), GenError> {
    let mut x: u8 = 0;
    if flags.delivery {
        x |= 0b01;
    }
    if flags.encryption {
        x |= 0b10;
    }
    x |= (match flags.lookup_type {
        DatabaseLookupType::Any => 0,
        DatabaseLookupType::LeaseSet => 1,
        DatabaseLookupType::RouterInfo => 2,
        DatabaseLookupType::Exploratory => 3,
    } << 2)
        & 0b1100;
    gen_be_u8!(input, x)
}

#[cfg_attr(rustfmt, rustfmt_skip)]
named!(
    database_lookup<MessagePayload>,
    do_parse!(
        key:            hash >>
        from:           hash >>
        flags:          database_lookup_flags >>
        reply_tid:      cond!(flags.delivery, call!(tunnel_id)) >>
        excluded_peers: length_count!(be_u16, hash) >>
        reply_enc:      cond!(flags.encryption, do_parse!(
            reply_key:  call!(session_key) >>
            tags:       length_count!(be_u8, session_tag) >>
            ((reply_key, tags))
        )) >>
        (MessagePayload::DatabaseLookup(DatabaseLookup {
            key,
            from,
            lookup_type: flags.lookup_type,
            reply_tid,
            excluded_peers,
            reply_enc,
        }))
    )
);

fn gen_database_lookup<'a>(
    input: (&'a mut [u8], usize),
    dl: &DatabaseLookup,
) -> Result<(&'a mut [u8], usize), GenError> {
    let flags = DatabaseLookupFlags {
        delivery: dl.reply_tid.is_some(),
        encryption: dl.reply_enc.is_some(),
        lookup_type: dl.lookup_type,
    };
    #[cfg_attr(rustfmt, rustfmt_skip)]
    do_gen!(
        input,
        gen_hash(&dl.key) >>
        gen_hash(&dl.from) >>
        gen_database_lookup_flags(&flags) >>
        gen_cond!(
            flags.delivery,
            do_gen!(gen_tunnel_id(dl.reply_tid.as_ref().unwrap()))
        ) >>
        gen_be_u16!(dl.excluded_peers.len() as u16) >>
        gen_many!(&dl.excluded_peers, gen_hash) >>
        gen_cond!(
            flags.encryption,
            do_gen!(
                gen_session_key(&dl.reply_enc.as_ref().unwrap().0) >>
                gen_be_u8!(dl.reply_enc.as_ref().unwrap().1.len() as u8) >>
                gen_many!(&dl.reply_enc.as_ref().unwrap().1, gen_session_tag)
            )
        )
    )
}

// DatabaseSearchReply

named!(
    database_search_reply<MessagePayload>,
    do_parse!(
        key: hash
            >> peers: length_count!(be_u8, hash)
            >> from: hash
            >> (MessagePayload::DatabaseSearchReply(DatabaseSearchReply { key, peers, from }))
    )
);

fn gen_database_search_reply<'a>(
    input: (&'a mut [u8], usize),
    dsr: &DatabaseSearchReply,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(
        input,
        gen_hash(&dsr.key)
            >> gen_be_u8!(dsr.peers.len() as u8)
            >> gen_many!(&dsr.peers, gen_hash)
            >> gen_hash(&dsr.from)
    )
}

// DeliveryStatus

named!(
    delivery_status<MessagePayload>,
    do_parse!(
        msg_id: be_u32
            >> time_stamp: i2p_date
            >> (MessagePayload::DeliveryStatus(DeliveryStatus { msg_id, time_stamp }))
    )
);

fn gen_delivery_status<'a>(
    input: (&'a mut [u8], usize),
    ds: &DeliveryStatus,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(
        input,
        gen_be_u32!(ds.msg_id) >> gen_i2p_date(&ds.time_stamp)
    )
}

// Garlic

#[cfg_attr(rustfmt, rustfmt_skip)]
named!(
    garlic_clove_delivery_instructions<GarlicCloveDeliveryInstructions>,
    do_parse!(
        flags: bits!(do_parse!(
            encrypted:     take_bits!(u8, 1) >>
            delivery_type: take_bits!(u8, 2) >>
            delay_set:     take_bits!(u8, 1) >>
                           take_bits!(u8, 4) >>
            (encrypted > 0, delivery_type, delay_set > 0)
        )) >>
        session_key: cond!(flags.0, call!(session_key)) >>
        to_hash:     cond!(flags.1 != 0, call!(hash)) >>
        tid:         cond!(flags.1 == 3, call!(tunnel_id)) >>
        delay:       cond!(flags.2, call!(be_u32)) >>
        (GarlicCloveDeliveryInstructions {
            encrypted: flags.0,
            delivery_type: flags.1,
            delay_set: flags.2,
            session_key,
            to_hash,
            tid,
            delay,
        })
    )
);

fn gen_garlic_clove_delivery_instructions<'a>(
    input: (&'a mut [u8], usize),
    gcdi: &GarlicCloveDeliveryInstructions,
) -> Result<(&'a mut [u8], usize), GenError> {
    let mut flags: u8 = 0b0000_0000;
    if gcdi.encrypted {
        flags |= 0b1000_0000;
    }
    flags |= (gcdi.delivery_type << 5) & 0b0110_0000;
    if gcdi.delay_set {
        flags |= 0b0001_0000;
    }
    #[cfg_attr(rustfmt, rustfmt_skip)]
    do_gen!(
        input,
        gen_be_u8!(flags) >>
        gen_cond!(
            gcdi.encrypted,
            do_gen!(gen_session_key(gcdi.session_key.as_ref().unwrap()))
        ) >>
        gen_cond!(
            gcdi.delivery_type != 0,
            do_gen!(gen_hash(gcdi.to_hash.as_ref().unwrap()))
        ) >>
        gen_cond!(
            gcdi.delivery_type == 3,
            do_gen!(gen_tunnel_id(gcdi.tid.as_ref().unwrap()))
        ) >>
        gen_cond!(
            gcdi.delay_set,
            do_gen!(gen_be_u32!(gcdi.delay.unwrap()))
        )
    )
}

#[cfg_attr(rustfmt, rustfmt_skip)]
named!(
    garlic_clove<GarlicClove>,
    do_parse!(
        delivery_instructions: garlic_clove_delivery_instructions >>
        msg:                   message >>
        clove_id:              be_u32 >>
        expiration:            i2p_date >>
        cert:                  certificate >>
        (GarlicClove {
            delivery_instructions,
            msg,
            clove_id,
            expiration,
            cert,
        })
    )
);

fn gen_garlic_clove<'a>(
    input: (&'a mut [u8], usize),
    clove: &GarlicClove,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(
        input,
        gen_garlic_clove_delivery_instructions(&clove.delivery_instructions)
            >> gen_message(&clove.msg)
            >> gen_be_u32!(clove.clove_id)
            >> gen_i2p_date(&clove.expiration)
            >> gen_certificate(&clove.cert)
    )
}

#[cfg_attr(rustfmt, rustfmt_skip)]
named!(
    garlic<MessagePayload>,
    do_parse!(
        cloves:     length_count!(be_u8, garlic_clove) >>
        cert:       certificate >>
        msg_id:     be_u32 >>
        expiration: i2p_date >>
        (MessagePayload::Garlic(Garlic {
            cloves,
            cert,
            msg_id,
            expiration,
        }))
    )
);

fn gen_garlic<'a>(
    input: (&'a mut [u8], usize),
    g: &Garlic,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(
        input,
        gen_be_u8!(g.cloves.len() as u8)
            >> gen_many!(&g.cloves, gen_garlic_clove)
            >> gen_certificate(&g.cert)
            >> gen_be_u32!(g.msg_id)
            >> gen_i2p_date(&g.expiration)
    )
}

// TunnelData

named!(
    tunnel_data<MessagePayload>,
    do_parse!(
        tid: tunnel_id
            >> data: take!(1024)
            >> (MessagePayload::TunnelData(TunnelData::from(tid, array_ref![data, 0, 1024])))
    )
);

fn gen_tunnel_data<'a>(
    input: (&'a mut [u8], usize),
    td: &TunnelData,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(input, gen_tunnel_id(&td.tid) >> gen_slice!(td.data))
}

// TunnelGateway

named!(
    tunnel_gateway<MessagePayload>,
    do_parse!(
        tid: tunnel_id
            >> data: length_bytes!(be_u16)
            >> (MessagePayload::TunnelGateway(TunnelGateway {
                tid,
                data: Vec::from(data),
            }))
    )
);

fn gen_tunnel_gateway<'a>(
    input: (&'a mut [u8], usize),
    tg: &TunnelGateway,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(input, gen_tunnel_id(&tg.tid) >> gen_slice!(tg.data))
}

// Data

named!(
    data<MessagePayload>,
    do_parse!(data: length_bytes!(be_u32) >> (MessagePayload::Data(Vec::from(data))))
);

fn gen_data<'a>(input: (&'a mut [u8], usize), d: &[u8]) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(input, gen_be_u32!(d.len()) >> gen_slice!(d))
}

// TunnelBuild

fn tunnel_build<'a>(input: &'a [u8]) -> IResult<&'a [u8], MessagePayload> {
    let (i, r) = count!(input, take!(528), 8)?;
    let mut xs = [[0u8; 528]; 8];
    for (i, &s) in r.iter().enumerate() {
        xs[i].copy_from_slice(s);
    }
    Ok((i, MessagePayload::TunnelBuild(xs)))
}

fn gen_tunnel_build<'a>(
    input: (&'a mut [u8], usize),
    tb: &[[u8; 528]; 8],
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(
        input,
        gen_slice!(tb[0])
            >> gen_slice!(tb[1])
            >> gen_slice!(tb[2])
            >> gen_slice!(tb[3])
            >> gen_slice!(tb[4])
            >> gen_slice!(tb[5])
            >> gen_slice!(tb[6])
            >> gen_slice!(tb[7])
    )
}

// TunnelBuildReply

fn tunnel_build_reply<'a>(input: &'a [u8]) -> IResult<&'a [u8], MessagePayload> {
    let (i, r) = count!(input, take!(528), 8)?;
    let mut xs = [[0u8; 528]; 8];
    for (i, &s) in r.iter().enumerate() {
        xs[i].copy_from_slice(s);
    }
    Ok((i, MessagePayload::TunnelBuildReply(xs)))
}

fn gen_tunnel_build_reply<'a>(
    input: (&'a mut [u8], usize),
    tb: &[[u8; 528]; 8],
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(
        input,
        gen_slice!(tb[0])
            >> gen_slice!(tb[1])
            >> gen_slice!(tb[2])
            >> gen_slice!(tb[3])
            >> gen_slice!(tb[4])
            >> gen_slice!(tb[5])
            >> gen_slice!(tb[6])
            >> gen_slice!(tb[7])
    )
}

// VariableTunnelBuild

fn variable_tunnel_build<'a>(input: &'a [u8]) -> IResult<&'a [u8], MessagePayload> {
    let (i, r) = length_count!(input, be_u8, take!(528))?;
    Ok((
        i,
        MessagePayload::VariableTunnelBuild(
            r.iter()
                .map(|&s| {
                    let mut x = [0u8; 528];
                    x.copy_from_slice(s);
                    x
                })
                .collect(),
        ),
    ))
}

fn gen_variable_tunnel_build<'a>(
    input: (&'a mut [u8], usize),
    tb: &[[u8; 528]],
) -> Result<(&'a mut [u8], usize), GenError> {
    // TODO: Fail if tb is too big
    let mut x = gen_be_u8!(input, tb.len() as u8)?;
    for record in tb {
        x = gen_slice!(x, record)?;
    }
    Ok(x)
}

// VariableTunnelBuildReply

fn variable_tunnel_build_reply<'a>(input: &'a [u8]) -> IResult<&'a [u8], MessagePayload> {
    let (i, r) = length_count!(input, be_u8, take!(528))?;
    Ok((
        i,
        MessagePayload::VariableTunnelBuildReply(
            r.iter()
                .map(|&s| {
                    let mut x = [0u8; 528];
                    x.copy_from_slice(s);
                    x
                })
                .collect(),
        ),
    ))
}

fn gen_variable_tunnel_build_reply<'a>(
    input: (&'a mut [u8], usize),
    tbr: &[[u8; 528]],
) -> Result<(&'a mut [u8], usize), GenError> {
    // TODO: Fail if tbr is too big
    let mut x = gen_be_u8!(input, tbr.len() as u8)?;
    for record in tbr {
        x = gen_slice!(x, record)?;
    }
    Ok(x)
}

//
// I2NP message framing
//

fn checksum(buf: &[u8]) -> u8 {
    let mut hasher = Sha256::default();
    hasher.input(&buf);
    let hash = hasher.result();
    hash[0]
}

fn validate_checksum<'a>(input: &'a [u8], cs: u8, buf: &[u8]) -> IResult<&'a [u8], ()> {
    if cs.eq(&checksum(&buf)) {
        Ok((input, ()))
    } else {
        Err(Err::Error(error_position!(input, ErrorKind::Custom(1))))
    }
}

fn gen_checksum(
    input: (&mut [u8], usize),
    start: usize,
    end: usize,
) -> Result<(&mut [u8], usize), GenError> {
    gen_be_u8!(input, checksum(&input.0[start..end]))
}

named!(
    header<(u8, u32, I2PDate, u16, u8)>,
    do_parse!(
        msg_type: be_u8
            >> msg_id: be_u32
            >> expiration: i2p_date
            >> size: be_u16
            >> cs: be_u8
            >> ((msg_type, msg_id, expiration, size, cs))
    )
);

named!(
    ntcp2_header<(u8, u32, I2PDate)>,
    do_parse!(
        msg_type: be_u8
            >> msg_id: be_u32
            >> expiration: short_expiry
            >> ((msg_type, msg_id, expiration))
    )
);

fn payload<'a>(input: &'a [u8], msg_type: u8) -> IResult<&'a [u8], MessagePayload> {
    switch!(input, value!(msg_type),
        1  => call!(database_store) |
        2  => call!(database_lookup) |
        3  => call!(database_search_reply) |
        10 => call!(delivery_status) |
        11 => call!(garlic) |
        18 => call!(tunnel_data) |
        19 => call!(tunnel_gateway) |
        20 => call!(data) |
        21 => call!(tunnel_build) |
        22 => call!(tunnel_build_reply) |
        23 => call!(variable_tunnel_build) |
        24 => call!(variable_tunnel_build_reply)
    )
}

named!(pub message<Message>,
    do_parse!(
        hdr:           header >>
        payload_bytes: peek!(take!(hdr.3)) >>
                       call!(validate_checksum, hdr.4, payload_bytes) >>
        payload: call!(payload, hdr.0) >>
        (Message {
            id: hdr.1,
            expiration: hdr.2,
            payload,
        })
    )
);

named!(pub ntcp2_message<Message>,
    do_parse!(
        hdr:     ntcp2_header >>
        payload: call!(payload, hdr.0) >>
        (Message {
            id: hdr.1,
            expiration: hdr.2,
            payload,
        })
    )
);

fn gen_message_type<'a>(
    input: (&'a mut [u8], usize),
    msg: &Message,
) -> Result<(&'a mut [u8], usize), GenError> {
    let msg_type = match msg.payload {
        MessagePayload::DatabaseStore(_) => 1,
        MessagePayload::DatabaseLookup(_) => 2,
        MessagePayload::DatabaseSearchReply(_) => 3,
        MessagePayload::DeliveryStatus(_) => 10,
        MessagePayload::Garlic(_) => 11,
        MessagePayload::TunnelData(_) => 18,
        MessagePayload::TunnelGateway(_) => 19,
        MessagePayload::Data(_) => 20,
        MessagePayload::TunnelBuild(_) => 21,
        MessagePayload::TunnelBuildReply(_) => 22,
        MessagePayload::VariableTunnelBuild(_) => 23,
        MessagePayload::VariableTunnelBuildReply(_) => 24,
    };
    gen_be_u8!(input, msg_type)
}

fn gen_payload<'a>(
    input: (&'a mut [u8], usize),
    payload: &MessagePayload,
) -> Result<(&'a mut [u8], usize), GenError> {
    match *payload {
        MessagePayload::DatabaseStore(ref ds) => gen_database_store(input, &ds),
        MessagePayload::DatabaseLookup(ref dl) => gen_database_lookup(input, &dl),
        MessagePayload::DatabaseSearchReply(ref dsr) => gen_database_search_reply(input, &dsr),
        MessagePayload::DeliveryStatus(ref ds) => gen_delivery_status(input, &ds),
        MessagePayload::Garlic(ref g) => gen_garlic(input, &g),
        MessagePayload::TunnelData(ref td) => gen_tunnel_data(input, &td),
        MessagePayload::TunnelGateway(ref tg) => gen_tunnel_gateway(input, &tg),
        MessagePayload::Data(ref d) => gen_data(input, &d),
        MessagePayload::TunnelBuild(tb) => gen_tunnel_build(input, &tb),
        MessagePayload::TunnelBuildReply(tbr) => gen_tunnel_build_reply(input, &tbr),
        MessagePayload::VariableTunnelBuild(ref vtb) => gen_variable_tunnel_build(input, &vtb),
        MessagePayload::VariableTunnelBuildReply(ref vtbr) => {
            gen_variable_tunnel_build_reply(input, &vtbr)
        }
    }
}

pub fn gen_message<'a>(
    input: (&'a mut [u8], usize),
    msg: &Message,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(input,
               gen_message_type(msg) >>
               gen_be_u32!(msg.id) >>
               gen_i2p_date(&msg.expiration) >>
        size:  gen_skip!(2) >>
        cs:    gen_skip!(1) >>
        start: gen_payload(&msg.payload) >>
        end:   gen_at_offset!(size, gen_be_u16!(end-start)) >>
               gen_at_offset!(cs, gen_checksum(start, end))
    )
}

pub fn gen_ntcp2_message<'a>(
    input: (&'a mut [u8], usize),
    msg: &Message,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(
        input,
        gen_message_type(msg)
            >> gen_be_u32!(msg.id)
            >> gen_short_expiry(&msg.expiration)
            >> gen_payload(&msg.payload)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::UNIX_EPOCH;

    macro_rules! bake_and_eat {
        ($oven:expr, $monster:expr, $value:expr, $expected:expr) => {
            let mut res = vec![];
            res.resize($expected.len(), 0);
            match $oven((&mut res, 0), &$value) {
                Ok(_) => assert_eq!(&res, &$expected),
                Err(e) => panic!("Unexpected error: {:?}", e),
            }
            match $monster(&res) {
                Ok((_, m)) => assert_eq!(m, $value),
                Err(e) => panic!("Unexpected error: {:?}", e),
            }
        };
    }

    #[test]
    fn test_build_request_record() {
        macro_rules! eval {
            ($value:expr) => {
                let mut res = vec![0; 222];
                if let Err(e) = gen_build_request_record((&mut res, 0), &$value) {
                    panic!("Unexpected error: {:?}", e);
                }
                match build_request_record(&res) {
                    Ok((_, m)) => assert_eq!(m, $value),
                    Err(e) => panic!("Unexpected error: {:?}", e),
                }
            };
        }

        eval!(BuildRequestRecord {
            receive_tid: TunnelId(7),
            our_ident: Hash([4; 32]),
            next_tid: TunnelId(2),
            next_ident: Hash([9; 32]),
            layer_key: SessionKey([6; 32]),
            iv_key: SessionKey([8; 32]),
            reply_key: SessionKey([1; 32]),
            reply_iv: [3; 16],
            hop_type: ParticipantType::Intermediate,
            request_time: 5,
            send_msg_id: 12,
        });

        eval!(BuildRequestRecord {
            receive_tid: TunnelId(0),
            our_ident: Hash([0; 32]),
            next_tid: TunnelId(0),
            next_ident: Hash([0; 32]),
            layer_key: SessionKey([0; 32]),
            iv_key: SessionKey([0; 32]),
            reply_key: SessionKey([0; 32]),
            reply_iv: [0; 16],
            hop_type: ParticipantType::InboundGateway,
            request_time: 0,
            send_msg_id: 0,
        });

        eval!(BuildRequestRecord {
            receive_tid: TunnelId(1),
            our_ident: Hash([2; 32]),
            next_tid: TunnelId(3),
            next_ident: Hash([4; 32]),
            layer_key: SessionKey([5; 32]),
            iv_key: SessionKey([6; 32]),
            reply_key: SessionKey([7; 32]),
            reply_iv: [8; 16],
            hop_type: ParticipantType::OutboundEndpoint,
            request_time: 9,
            send_msg_id: 10,
        });
    }

    #[test]
    fn test_build_request_record_flags() {
        macro_rules! eval {
            ($flag:expr, $value:expr) => {
                let mut encoded = vec![0; 222];
                encoded[184] = $flag;
                assert_eq!(build_request_record(&encoded).map(|(_, v)| v), $value);
            };
        }

        // No flag bits set
        eval!(
            0,
            Ok(BuildRequestRecord {
                receive_tid: TunnelId(0),
                our_ident: Hash([0; 32]),
                next_tid: TunnelId(0),
                next_ident: Hash([0; 32]),
                layer_key: SessionKey([0; 32]),
                iv_key: SessionKey([0; 32]),
                reply_key: SessionKey([0; 32]),
                reply_iv: [0; 16],
                hop_type: ParticipantType::Intermediate,
                request_time: 0,
                send_msg_id: 0,
            })
        );

        // Flag bit 7 set
        eval!(
            0x80,
            Ok(BuildRequestRecord {
                receive_tid: TunnelId(0),
                our_ident: Hash([0; 32]),
                next_tid: TunnelId(0),
                next_ident: Hash([0; 32]),
                layer_key: SessionKey([0; 32]),
                iv_key: SessionKey([0; 32]),
                reply_key: SessionKey([0; 32]),
                reply_iv: [0; 16],
                hop_type: ParticipantType::InboundGateway,
                request_time: 0,
                send_msg_id: 0,
            })
        );

        // Flag bit 6 set
        eval!(
            0x40,
            Ok(BuildRequestRecord {
                receive_tid: TunnelId(0),
                our_ident: Hash([0; 32]),
                next_tid: TunnelId(0),
                next_ident: Hash([0; 32]),
                layer_key: SessionKey([0; 32]),
                iv_key: SessionKey([0; 32]),
                reply_key: SessionKey([0; 32]),
                reply_iv: [0; 16],
                hop_type: ParticipantType::OutboundEndpoint,
                request_time: 0,
                send_msg_id: 0,
            })
        );

        // Flag bits 7 and 6 set
        eval!(
            0xc0,
            Err(nom::Err::Error(nom::Context::Code(
                &vec![
                    0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ][..],
                nom::ErrorKind::Verify
            )))
        );
    }

    #[test]
    fn test_build_response_record() {
        macro_rules! eval {
            ($value:expr) => {
                let mut res = vec![0; 528];
                if let Err(e) = gen_build_response_record((&mut res, 0), &$value) {
                    panic!("Unexpected error: {:?}", e);
                }
                match build_response_record(&res) {
                    Ok((_, m)) => assert_eq!(m, $value),
                    Err(e) => panic!("Unexpected error: {:?}", e),
                }
            };
        }

        eval!(BuildResponseRecord { reply: 0 });
        eval!(BuildResponseRecord { reply: 10 });
        eval!(BuildResponseRecord { reply: 20 });
        eval!(BuildResponseRecord { reply: 30 });
        eval!(BuildResponseRecord { reply: 40 });
        eval!(BuildResponseRecord { reply: 255 });
    }

    #[test]
    fn test_database_lookup_flags() {
        macro_rules! eval {
            ($value:expr, $expected:expr) => {
                bake_and_eat!(
                    gen_database_lookup_flags,
                    database_lookup_flags,
                    $value,
                    $expected
                )
            };
        }

        eval!(
            DatabaseLookupFlags {
                delivery: false,
                encryption: false,
                lookup_type: DatabaseLookupType::Any,
            },
            [0]
        );

        eval!(
            DatabaseLookupFlags {
                delivery: true,
                encryption: false,
                lookup_type: DatabaseLookupType::LeaseSet,
            },
            [5]
        );

        eval!(
            DatabaseLookupFlags {
                delivery: false,
                encryption: true,
                lookup_type: DatabaseLookupType::RouterInfo,
            },
            [10]
        );

        eval!(
            DatabaseLookupFlags {
                delivery: true,
                encryption: true,
                lookup_type: DatabaseLookupType::Exploratory,
            },
            [15]
        );
    }

    #[test]
    fn test_validate_checksum() {
        let a = b"payloadspam";
        assert_eq!(validate_checksum(&a[..], 0x23, &a[..7]), Ok((&a[..], ())));
        assert_eq!(
            validate_checksum(&a[..], 0x23, &a[..8]),
            Err(Err::Error(error_position!(&a[..], ErrorKind::Custom(1))))
        );
    }

    #[test]
    fn test_gen_checksum() {
        // Valid payload checksum
        let a = b"#payloadspam";
        // Copy payload into a buffer with an empty checksum
        let mut b = Vec::new();
        b.push(0);
        b.extend(a[1..].iter().cloned());
        // Generate and validate checksum of payload
        let res = gen_checksum((&mut b[..], 0), 1, 8);
        assert!(res.is_ok());
        let (o, n) = res.unwrap();
        assert_eq!(o, &a[..]);
        assert_eq!(n, 1);
    }

    #[test]
    fn test_message() {
        macro_rules! eval {
            ($value:expr, $expected:expr) => {
                bake_and_eat!(gen_message, message, $value, $expected)
            };
        }

        eval!(
            Message {
                id: 0,
                expiration: I2PDate::from_system_time(UNIX_EPOCH),
                payload: MessagePayload::Data(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]),
            },
            [
                20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 14, 44, 0, 0, 0, 10, 0, 1, 2, 3, 4, 5,
                6, 7, 8, 9,
            ]
        );

        eval!(
            Message {
                id: 0x1234_5678,
                expiration: I2PDate::from_system_time(UNIX_EPOCH),
                payload: MessagePayload::DeliveryStatus(DeliveryStatus {
                    msg_id: 0x7b3f_bba9,
                    time_stamp: I2PDate::from_system_time(UNIX_EPOCH)
                }),
            },
            [
                0x0a, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x0c, 0xf9, 0x7b, 0x3f, 0xbb, 0xa9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ]
        );
    }

    #[test]
    fn test_ntcp2_message() {
        macro_rules! eval {
            ($value:expr, $expected:expr) => {
                bake_and_eat!(gen_ntcp2_message, ntcp2_message, $value, $expected)
            };
        }

        eval!(
            Message {
                id: 0,
                expiration: I2PDate::from_system_time(UNIX_EPOCH),
                payload: MessagePayload::Data(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]),
            },
            [20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,]
        );

        eval!(
            Message {
                id: 0x1234_5678,
                expiration: I2PDate::from_system_time(UNIX_EPOCH),
                payload: MessagePayload::DeliveryStatus(DeliveryStatus {
                    msg_id: 0x7b3f_bba9,
                    time_stamp: I2PDate::from_system_time(UNIX_EPOCH)
                }),
            },
            [
                0x0a, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x00, 0x7b, 0x3f, 0xbb, 0xa9, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ]
        );
    }
}
