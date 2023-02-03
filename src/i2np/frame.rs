use cookie_factory::*;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use nom::*;
use nom::{
    bits::streaming::take as take_bits,
    bytes::streaming::take,
    combinator::{cond, map, map_opt, peek, verify},
    error::{Error as NomError, ErrorKind},
    multi::{count, length_count, length_data},
    number::streaming::{be_u16, be_u32, be_u8},
    sequence::{pair, preceded, terminated, tuple},
};
use rand::rngs::OsRng;
use sha2::{
    digest::generic_array::{typenum::U32, GenericArray},
    Digest, Sha256,
};
use std::io::{Read, Write};

use super::*;
use crate::crypto::frame::{gen_session_key, session_key};
use crate::data::{
    dest::frame::{gen_lease_set, lease_set},
    frame::{
        certificate, gen_certificate, gen_hash, gen_i2p_date, gen_router_info, gen_session_tag,
        gen_short_expiry, gen_tunnel_id, hash, i2p_date, router_info, session_tag, short_expiry,
        tunnel_id,
    },
};

//
// Utils
//

fn iv(input: &[u8]) -> IResult<&[u8], [u8; 16]> {
    let (i, iv) = take(16usize)(input)?;
    let mut x = [0u8; 16];
    x.copy_from_slice(iv);
    Ok((i, x))
}

//
// Common structures
//

pub fn build_request_record(i: &[u8]) -> IResult<&[u8], BuildRequestRecord> {
    map(
        terminated(
            tuple((
                tunnel_id,
                hash,
                tunnel_id,
                hash,
                session_key,
                session_key,
                session_key,
                iv,
                map(
                    verify(
                        map(
                            bits(terminated(
                                tuple((take_bits(1u8), take_bits(1u8))),
                                take_bits::<_, u8, _, NomError<_>>(6u8),
                            )),
                            |(ibgw, obep): (u8, u8)| (ibgw > 0, obep > 0),
                        ),
                        |(ibgw, obep)| !(*ibgw && *obep),
                    ),
                    |(ibgw, obep)| match (ibgw, obep) {
                        (false, false) => ParticipantType::Intermediate,
                        (true, false) => ParticipantType::InboundGateway,
                        (false, true) => ParticipantType::OutboundEndpoint,
                        (true, true) => unreachable!(),
                    },
                ),
                be_u32,
                be_u32,
            )),
            take(29usize),
        ),
        |(
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
        )| BuildRequestRecord {
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
        },
    )(i)
}

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
    let mut rng = OsRng;
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
    hasher.update(padding);
    hasher.update(&[reply]);
    hasher.finalize()
}

pub fn build_response_record(i: &[u8]) -> IResult<&[u8], BuildResponseRecord> {
    map_opt(
        tuple((hash, take(495usize), be_u8)),
        |(hash, padding, reply)| {
            let res = calculate_build_response_record_hash(padding, reply);
            if hash.eq(&Hash::from_bytes(array_ref![res, 0, 32])) {
                Some(BuildResponseRecord { reply })
            } else {
                None
            }
        },
    )(i)
}

pub fn gen_build_response_record<'a>(
    input: (&'a mut [u8], usize),
    brr: &BuildResponseRecord,
) -> Result<(&'a mut [u8], usize), GenError> {
    let mut padding = vec![0; 495];
    let mut rng = OsRng;
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

fn compressed_ri(input: &[u8]) -> IResult<&[u8], RouterInfo> {
    let (i, payload) = length_data(be_u16)(input)?;
    let mut buf = Vec::new();
    let mut d = GzDecoder::new(payload);
    match d.read_to_end(&mut buf) {
        Ok(_) => match router_info(&buf) {
            Ok((_, ri)) => Ok((i, ri)),
            Err(Err::Incomplete(n)) => Err(Err::Incomplete(n)),
            Err(Err::Error(NomError { code, .. })) => Err(Err::Error(NomError::new(input, code))),
            Err(Err::Failure(NomError { code, .. })) => {
                Err(Err::Failure(NomError::new(input, code)))
            }
        },
        Err(_) => Err(Err::Error(NomError::new(input, ErrorKind::Eof))),
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

fn reply_path(i: &[u8]) -> IResult<&[u8], Option<ReplyPath>> {
    let (i, reply_tok) = be_u32(i)?;
    cond(
        reply_tok > 0,
        map(pair(tunnel_id, hash), move |(reply_tid, reply_gw)| {
            ReplyPath {
                token: reply_tok,
                tid: reply_tid,
                gateway: reply_gw,
            }
        }),
    )(i)
}

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

fn database_store(i: &[u8]) -> IResult<&[u8], MessagePayload> {
    let (i, (key, ds_type)) = pair(hash, be_u8)(i)?;
    let (i, reply) = reply_path(i)?;
    let (i, data) = match ds_type {
        0 => map(map(compressed_ri, Box::new), DatabaseStoreData::RI)(i),
        1 => map(map(lease_set, Box::new), DatabaseStoreData::LS)(i),
        _ => unimplemented!(),
    }?;
    Ok((
        i,
        MessagePayload::DatabaseStore(DatabaseStore {
            key,
            ds_type,
            reply,
            data,
        }),
    ))
}

fn gen_database_store_data<'a>(
    input: (&'a mut [u8], usize),
    data: &DatabaseStoreData,
) -> Result<(&'a mut [u8], usize), GenError> {
    match *data {
        DatabaseStoreData::RI(ref ri) => gen_compressed_ri(input, ri),
        DatabaseStoreData::LS(ref ls) => gen_lease_set(input, ls),
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

fn database_lookup_flags(i: &[u8]) -> IResult<&[u8], DatabaseLookupFlags> {
    map(
        bits::<_, _, NomError<_>, _, _>(preceded(
            take_bits::<_, u8, _, _>(4u8),
            tuple((take_bits(2u8), take_bits(1u8), take_bits(1u8))),
        )),
        |(lookup_type, encryption, delivery): (u8, u8, u8)| DatabaseLookupFlags {
            delivery: delivery > 0,
            encryption: encryption > 0,
            lookup_type: match lookup_type {
                0 => DatabaseLookupType::Any,
                1 => DatabaseLookupType::LeaseSet,
                2 => DatabaseLookupType::RouterInfo,
                3 => DatabaseLookupType::Exploratory,
                _ => unreachable!(),
            },
        },
    )(i)
}

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

fn database_lookup(i: &[u8]) -> IResult<&[u8], MessagePayload> {
    let (i, (key, from, flags)) = tuple((hash, hash, database_lookup_flags))(i)?;
    let (i, (reply_tid, excluded_peers, reply_enc)) = tuple((
        cond(flags.delivery, tunnel_id),
        length_count(be_u16, hash),
        cond(
            flags.encryption,
            pair(session_key, length_count(be_u8, session_tag)),
        ),
    ))(i)?;
    Ok((
        i,
        MessagePayload::DatabaseLookup(DatabaseLookup {
            key,
            from,
            lookup_type: flags.lookup_type,
            reply_tid,
            excluded_peers,
            reply_enc,
        }),
    ))
}

#[rustfmt::skip]
fn gen_database_lookup<'a>(
    input: (&'a mut [u8], usize),
    dl: &DatabaseLookup,
) -> Result<(&'a mut [u8], usize), GenError> {
    let flags = DatabaseLookupFlags {
        delivery: dl.reply_tid.is_some(),
        encryption: dl.reply_enc.is_some(),
        lookup_type: dl.lookup_type,
    };
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

fn database_search_reply(i: &[u8]) -> IResult<&[u8], MessagePayload> {
    map(
        tuple((hash, length_count(be_u8, hash), hash)),
        |(key, peers, from)| {
            MessagePayload::DatabaseSearchReply(DatabaseSearchReply { key, peers, from })
        },
    )(i)
}

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

fn delivery_status(i: &[u8]) -> IResult<&[u8], MessagePayload> {
    map(pair(be_u32, i2p_date), |(msg_id, time_stamp)| {
        MessagePayload::DeliveryStatus(DeliveryStatus { msg_id, time_stamp })
    })(i)
}

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

fn garlic_clove_delivery_instructions(i: &[u8]) -> IResult<&[u8], GarlicCloveDeliveryInstructions> {
    let (i, (encrypted, delivery_type, delay_set)) = map(
        bits(terminated(
            tuple((take_bits(1u8), take_bits(2u8), take_bits(1u8))),
            take_bits::<_, u8, _, NomError<_>>(4u8),
        )),
        |(encrypted, delivery_type, delay_set): (u8, u8, u8)| {
            (encrypted > 0, delivery_type, delay_set > 0)
        },
    )(i)?;
    map(
        tuple((
            cond(encrypted, session_key),
            cond(delivery_type != 0, hash),
            cond(delivery_type == 3, tunnel_id),
            cond(delay_set, be_u32),
        )),
        move |(session_key, to_hash, tid, delay)| GarlicCloveDeliveryInstructions {
            encrypted,
            delivery_type,
            delay_set,
            session_key,
            to_hash,
            tid,
            delay,
        },
    )(i)
}

#[rustfmt::skip]
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

fn garlic_clove(i: &[u8]) -> IResult<&[u8], GarlicClove> {
    map(
        tuple((
            garlic_clove_delivery_instructions,
            message,
            be_u32,
            i2p_date,
            certificate,
        )),
        |(delivery_instructions, msg, clove_id, expiration, cert)| GarlicClove {
            delivery_instructions,
            msg,
            clove_id,
            expiration,
            cert,
        },
    )(i)
}

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

fn garlic(i: &[u8]) -> IResult<&[u8], MessagePayload> {
    map(
        tuple((
            length_count(be_u8, garlic_clove),
            certificate,
            be_u32,
            i2p_date,
        )),
        |(cloves, cert, msg_id, expiration)| {
            MessagePayload::Garlic(Garlic {
                cloves,
                cert,
                msg_id,
                expiration,
            })
        },
    )(i)
}

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

fn tunnel_data(i: &[u8]) -> IResult<&[u8], MessagePayload> {
    map(pair(tunnel_id, take(1024usize)), |(tid, data)| {
        MessagePayload::TunnelData(TunnelData::new(tid, array_ref![data, 0, 1024]))
    })(i)
}

fn gen_tunnel_data<'a>(
    input: (&'a mut [u8], usize),
    td: &TunnelData,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(input, gen_tunnel_id(&td.tid) >> gen_slice!(td.data))
}

// TunnelGateway

fn tunnel_gateway(i: &[u8]) -> IResult<&[u8], MessagePayload> {
    map(pair(tunnel_id, length_data(be_u16)), |(tid, data)| {
        MessagePayload::TunnelGateway(TunnelGateway {
            tid,
            data: Vec::from(data),
        })
    })(i)
}

fn gen_tunnel_gateway<'a>(
    input: (&'a mut [u8], usize),
    tg: &TunnelGateway,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(input, gen_tunnel_id(&tg.tid) >> gen_slice!(tg.data))
}

// Data

fn data(i: &[u8]) -> IResult<&[u8], MessagePayload> {
    map(length_data(be_u32), |data| {
        MessagePayload::Data(Vec::from(data))
    })(i)
}

fn gen_data<'a>(input: (&'a mut [u8], usize), d: &[u8]) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(input, gen_be_u32!(d.len()) >> gen_slice!(d))
}

// TunnelBuild

fn tunnel_build(input: &[u8]) -> IResult<&[u8], MessagePayload> {
    let (i, r) = count(take(528usize), 8)(input)?;
    let mut xs = Box::new([[0u8; 528]; 8]);
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

fn tunnel_build_reply(input: &[u8]) -> IResult<&[u8], MessagePayload> {
    let (i, r) = count(take(528usize), 8)(input)?;
    let mut xs = Box::new([[0u8; 528]; 8]);
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

fn variable_tunnel_build(input: &[u8]) -> IResult<&[u8], MessagePayload> {
    let (i, r) = length_count(be_u8, take(528usize))(input)?;
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

fn variable_tunnel_build_reply(input: &[u8]) -> IResult<&[u8], MessagePayload> {
    let (i, r) = length_count(be_u8, take(528usize))(input)?;
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
    Sha256::digest(buf)[0]
}

fn gen_checksum(
    input: (&mut [u8], usize),
    start: usize,
    end: usize,
) -> Result<(&mut [u8], usize), GenError> {
    gen_be_u8!(input, checksum(&input.0[start..end]))
}

fn header(i: &[u8]) -> IResult<&[u8], (u8, u32, I2PDate, u16, u8)> {
    // (msg_type, msg_id, expiration, size, cs)
    tuple((be_u8, be_u32, i2p_date, be_u16, be_u8))(i)
}

fn ntcp2_header(i: &[u8]) -> IResult<&[u8], (u8, u32, I2PDate)> {
    // (msg_type, msg_id, expiration)
    tuple((be_u8, be_u32, short_expiry))(i)
}

fn payload(msg_type: u8) -> impl Fn(&[u8]) -> IResult<&[u8], MessagePayload> {
    move |i: &[u8]| match msg_type {
        1 => database_store(i),
        2 => database_lookup(i),
        3 => database_search_reply(i),
        10 => delivery_status(i),
        11 => garlic(i),
        18 => tunnel_data(i),
        19 => tunnel_gateway(i),
        20 => data(i),
        21 => tunnel_build(i),
        22 => tunnel_build_reply(i),
        23 => variable_tunnel_build(i),
        24 => variable_tunnel_build_reply(i),
        _ => unimplemented!(),
    }
}

pub fn message(i: &[u8]) -> IResult<&[u8], Message> {
    let (i, (msg_type, id, expiration, size, cs)) = header(i)?;
    map(
        preceded(
            peek(verify(take(size), move |buf| checksum(buf) == cs)),
            payload(msg_type),
        ),
        move |payload| Message {
            id,
            expiration,
            payload,
        },
    )(i)
}

pub fn ntcp2_message(i: &[u8]) -> IResult<&[u8], Message> {
    let (i, hdr) = ntcp2_header(i)?;
    let (i, payload) = payload(hdr.0)(i)?;
    Ok((
        i,
        Message {
            id: hdr.1,
            expiration: hdr.2,
            payload,
        },
    ))
}

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
    match payload {
        MessagePayload::DatabaseStore(ref ds) => gen_database_store(input, ds),
        MessagePayload::DatabaseLookup(ref dl) => gen_database_lookup(input, dl),
        MessagePayload::DatabaseSearchReply(ref dsr) => gen_database_search_reply(input, dsr),
        MessagePayload::DeliveryStatus(ref ds) => gen_delivery_status(input, ds),
        MessagePayload::Garlic(ref g) => gen_garlic(input, g),
        MessagePayload::TunnelData(ref td) => gen_tunnel_data(input, td),
        MessagePayload::TunnelGateway(ref tg) => gen_tunnel_gateway(input, tg),
        MessagePayload::Data(ref d) => gen_data(input, d),
        MessagePayload::TunnelBuild(tb) => gen_tunnel_build(input, tb),
        MessagePayload::TunnelBuildReply(tbr) => gen_tunnel_build_reply(input, tbr),
        MessagePayload::VariableTunnelBuild(ref vtb) => gen_variable_tunnel_build(input, vtb),
        MessagePayload::VariableTunnelBuildReply(ref vtbr) => {
            gen_variable_tunnel_build_reply(input, vtbr)
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

    use nom::error::Error as NomError;

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
            Err(nom::Err::Error(NomError {
                input: &vec![
                    0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ][..],
                code: nom::error::ErrorKind::Verify
            }))
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
    fn test_gen_checksum() {
        // Valid payload checksum
        let a = b"#payloadspam";
        // Copy payload into a buffer with an empty checksum
        let mut b = vec![0];
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
