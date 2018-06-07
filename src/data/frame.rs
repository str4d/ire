use cookie_factory::*;
use itertools::Itertools;
use nom::{be_u16, be_u32, be_u64, be_u8, Err, ErrorKind};

use super::*;
use constants;
use crypto::frame::{enc_type, gen_enc_type, gen_private_key, gen_public_key, gen_sig_type,
                    gen_signature, gen_signing_key, gen_signing_private_key, private_key,
                    public_key, sig_type, signature, signing_key, signing_private_key};

//
// Simple data types
//

named!(pub hash<Hash>, do_parse!(
    h: take!(32) >> (Hash::from_bytes(array_ref![h, 0, 32]))
));
pub fn gen_hash<'a>(
    input: (&'a mut [u8], usize),
    h: &Hash,
) -> Result<(&'a mut [u8], usize), GenError> {
    gen_slice!(input, h.0)
}

named!(pub i2p_date<I2PDate>, do_parse!(
    date: be_u64 >> (I2PDate(date))
));
pub fn gen_i2p_date<'a>(
    input: (&'a mut [u8], usize),
    date: &I2PDate,
) -> Result<(&'a mut [u8], usize), GenError> {
    gen_be_u64!(input, date.0)
}

named!(pub i2p_string<I2PString>, do_parse!(
    len: be_u8 >> s: take_str!(len) >> (I2PString(String::from(s)))
));
pub fn gen_i2p_string<'a>(
    input: (&'a mut [u8], usize),
    s: &I2PString,
) -> Result<(&'a mut [u8], usize), GenError> {
    let buf = s.0.as_bytes();
    do_gen!(input, gen_be_u8!(buf.len() as u8) >> gen_slice!(buf))
}

named!(pub mapping<Mapping>,
    do_parse!(
        pairs: length_value!(be_u16, many0!(complete!(
            terminated!(separated_pair!(i2p_string, tag!("="), i2p_string), tag!(";"))
        ))) >>
        (Mapping(pairs.into_iter().collect()))
    )
);
pub fn gen_mapping_pair<'a>(
    input: (&'a mut [u8], usize),
    pair: (&I2PString, &I2PString),
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(
        input,
        gen_i2p_string(pair.0) >> gen_slice!("=".as_bytes()) >> gen_i2p_string(pair.1)
            >> gen_slice!(";".as_bytes())
    )
}
pub fn gen_mapping<'a>(
    input: (&'a mut [u8], usize),
    m: &Mapping,
) -> Result<(&'a mut [u8], usize), GenError> {
    #[cfg_attr(rustfmt, rustfmt_skip)]
    do_gen!(
        input,
        size:  gen_skip!(2) >>
        // Some structures require the Mapping be sorted, so just sort them all
        start: gen_many!(m.0.iter().sorted().into_iter(), gen_mapping_pair) >>
        end:   gen_at_offset!(size, gen_be_u16!(end - start))
    )
}

named!(pub session_tag<SessionTag>, do_parse!(
    t: take!(32) >> (SessionTag::from_bytes(array_ref![t, 0, 32]))
));
pub fn gen_session_tag<'a>(
    input: (&'a mut [u8], usize),
    t: &SessionTag,
) -> Result<(&'a mut [u8], usize), GenError> {
    gen_slice!(input, t.0)
}

named!(pub tunnel_id<TunnelId>, do_parse!(
    tid: be_u32 >> (TunnelId(tid))
));
pub fn gen_tunnel_id<'a>(
    input: (&'a mut [u8], usize),
    tid: &TunnelId,
) -> Result<(&'a mut [u8], usize), GenError> {
    gen_be_u32!(input, tid.0)
}

// SigningPublicKey

fn split_signing_key<'a>(
    input: &'a [u8],
    base_data: &[u8; constants::KEYCERT_SIGKEY_BYTES],
    cert: &Certificate,
) -> IResult<&'a [u8], SigningPublicKey> {
    let res = match cert {
        &Certificate::Key(ref kc) => {
            if kc.sig_type.extra_data_len(&kc.enc_type) > 0 {
                let mut data = Vec::from(&base_data[..]);
                data.extend(&kc.sig_data);
                SigningPublicKey::from_bytes(&kc.sig_type, &data)
            } else {
                let pad = kc.sig_type.pad_len(&kc.enc_type);
                SigningPublicKey::from_bytes(&kc.sig_type, &base_data[pad..])
            }
        }
        _ => SigningPublicKey::from_bytes(&SigType::DsaSha1, &base_data[..]),
    };
    match res {
        Ok(spk) => Ok((input, spk)),
        Err(_) => Err(Err::Error(error_position!(input, ErrorKind::Custom(1)))),
    }
}

fn gen_truncated_signing_key<'a>(
    input: (&'a mut [u8], usize),
    key: &SigningPublicKey,
) -> Result<(&'a mut [u8], usize), GenError> {
    if key.as_bytes().len() > constants::KEYCERT_SIGKEY_BYTES {
        gen_slice!(input, key.as_bytes()[0..constants::KEYCERT_SIGKEY_BYTES])
    } else {
        gen_slice!(input, key.as_bytes())
    }
}

// KeyCertificate

fn keycert_padding<'a>(
    input: &'a [u8],
    base_data: &[u8; 128],
    cert: &Certificate,
) -> IResult<&'a [u8], Option<Vec<u8>>> {
    let spk = match cert {
        &Certificate::Key(ref kc) => {
            let pad_len = kc.sig_type.pad_len(&kc.enc_type);
            if pad_len > 0 {
                Some(Vec::from(&base_data[0..pad_len]))
            } else {
                None
            }
        }
        _ => None,
    };
    Ok((input, spk))
}

#[cfg_attr(rustfmt, rustfmt_skip)]
named!(
    key_certificate<KeyCertificate>,
    do_parse!(
        sig_type: sig_type >>
        enc_type: enc_type >>
        sig_data: take!(sig_type.extra_data_len(&enc_type)) >>
        enc_data: take!(enc_type.extra_data_len(&sig_type)) >>
        (KeyCertificate {
            sig_type,
            enc_type,
            sig_data: Vec::from(sig_data),
            enc_data: Vec::from(enc_data),
        })
    )
);

fn gen_key_certificate<'a>(
    input: (&'a mut [u8], usize),
    kc: &KeyCertificate,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(
        input,
        gen_sig_type(&kc.sig_type) >> gen_enc_type(&kc.enc_type) >> gen_slice!(&kc.sig_data)
            >> gen_slice!(&kc.enc_data)
    )
}

// Certificate

named!(pub certificate<Certificate>,
    switch!(be_u8,
        constants::NULL_CERT => value!(Certificate::Null) |
        constants::HASH_CERT => do_parse!(
            payload: length_bytes!(be_u16) >>
            (Certificate::HashCash(Vec::from(payload)))
        ) |
        constants::HIDDEN_CERT => value!(Certificate::Hidden) |
        constants::SIGNED_CERT => do_parse!(
            payload: length_bytes!(be_u16) >>
            (Certificate::Signed(Vec::from(payload)))
        ) |
        constants::MULTI_CERT => do_parse!(
            payload: length_bytes!(be_u16) >>
            (Certificate::Multiple(Vec::from(payload)))
        ) |
        constants::KEY_CERT => do_parse!(
            len:  be_u16 >>
            cert: key_certificate >>
            (Certificate::Key(cert))
        )
    )
);

pub fn gen_certificate<'a>(
    input: (&'a mut [u8], usize),
    cert: &Certificate,
) -> Result<(&'a mut [u8], usize), GenError> {
    #[cfg_attr(rustfmt, rustfmt_skip)]
    match cert {
        &Certificate::Null => gen_be_u8!(input, constants::NULL_CERT),
        &Certificate::HashCash(ref payload) => do_gen!(
            input,
            gen_be_u8!(constants::HASH_CERT) >>
            gen_be_u16!(payload.len() as u16) >>
            gen_slice!(&payload)
        ),
        &Certificate::Hidden => gen_be_u8!(input, constants::HIDDEN_CERT),
        &Certificate::Signed(ref payload) => do_gen!(
            input,
            gen_be_u8!(constants::SIGNED_CERT) >>
            gen_be_u16!(payload.len() as u16) >>
            gen_slice!(&payload)
        ),
        &Certificate::Multiple(ref payload) => do_gen!(
            input,
            gen_be_u8!(constants::MULTI_CERT) >>
            gen_be_u16!(payload.len() as u16) >>
            gen_slice!(&payload)
        ),
        &Certificate::Key(ref kc) => do_gen!(
            input,
                   gen_be_u8!(constants::KEY_CERT) >>
            size:  gen_skip!(2) >>
            start: gen_key_certificate(&kc) >>
            end:   gen_at_offset!(size, gen_be_u16!(end - start))
        ),
    }
}

// RouterIdentity

named!(pub router_identity<RouterIdentity>,
    do_parse!(
        public_key:   public_key >>
        signing_data: take!(constants::KEYCERT_SIGKEY_BYTES) >>
        certificate:  certificate >>
        padding:      call!(keycert_padding,
                            array_ref![signing_data, 0, constants::KEYCERT_SIGKEY_BYTES],
                            &certificate) >>
        signing_key:  call!(split_signing_key,
                            array_ref![signing_data, 0, constants::KEYCERT_SIGKEY_BYTES],
                            &certificate) >>
        (RouterIdentity {
            public_key,
            padding,
            signing_key,
            certificate,
        })
    )
);

pub fn gen_router_identity<'a>(
    input: (&'a mut [u8], usize),
    rid: &RouterIdentity,
) -> Result<(&'a mut [u8], usize), GenError> {
    #[cfg_attr(rustfmt, rustfmt_skip)]
    do_gen!(
        input,
        gen_public_key(&rid.public_key) >>
        gen_cond!(
            rid.padding.is_some(),
            gen_slice!(rid.padding.as_ref().unwrap())
        ) >>
        gen_truncated_signing_key(&rid.signing_key) >>
        gen_certificate(&rid.certificate)
    )
}

// RouterSecretKeys

named!(pub router_secret_keys<RouterSecretKeys>,
    do_parse!(
        rid: router_identity >>
        private_key: private_key >>
        signing_private_key: call!(signing_private_key, rid.signing_key.sig_type()) >>
        (RouterSecretKeys { rid, private_key, signing_private_key })
    )
);

pub fn gen_router_secret_keys<'a>(
    input: (&'a mut [u8], usize),
    rsk: &RouterSecretKeys,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(
        input,
        gen_router_identity(&rsk.rid) >> gen_private_key(&rsk.private_key)
            >> gen_signing_private_key(&rsk.signing_private_key)
    )
}

// Destination

#[cfg_attr(rustfmt, rustfmt_skip)]
named!(
    destination<Destination>,
    do_parse!(
        public_key:   public_key >>
        signing_data: take!(constants::KEYCERT_SIGKEY_BYTES) >>
        certificate:  certificate >>
        padding:      call!(
            keycert_padding,
            array_ref![signing_data, 0, constants::KEYCERT_SIGKEY_BYTES],
            &certificate
        ) >>
        signing_key:  call!(
            split_signing_key,
            array_ref![signing_data, 0, constants::KEYCERT_SIGKEY_BYTES],
            &certificate
        ) >>
        (Destination {
            public_key,
            padding,
            signing_key,
            certificate,
        })
    )
);

fn gen_destination<'a>(
    input: (&'a mut [u8], usize),
    dest: &Destination,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(
        input,
        gen_public_key(&dest.public_key)
            >> gen_cond!(
                dest.padding.is_some(),
                gen_slice!(dest.padding.as_ref().unwrap())
            ) >> gen_truncated_signing_key(&dest.signing_key)
            >> gen_certificate(&dest.certificate)
    )
}

// Lease

#[cfg_attr(rustfmt, rustfmt_skip)]
named!(
    lease<Lease>,
    do_parse!(
        tunnel_gw: hash >>
        tid:       tunnel_id >>
        end_date:  i2p_date >>
        (Lease {
            tunnel_gw,
            tid,
            end_date,
        })
    )
);

fn gen_lease<'a>(
    input: (&'a mut [u8], usize),
    lease: &Lease,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(
        input,
        gen_hash(&lease.tunnel_gw) >> gen_tunnel_id(&lease.tid) >> gen_i2p_date(&lease.end_date)
    )
}

// LeaseSet

named!(pub lease_set<LeaseSet>,
    do_parse!(
        dest:    destination >>
        enc_key: public_key >>
        sig_key: call!(signing_key, dest.signing_key.sig_type()) >>
        leases:  length_count!(be_u8, lease) >>
        sig:     call!(signature, &dest.signing_key.sig_type()) >>
        (LeaseSet {
            sig_key,
            dest,
            enc_key,
            leases,
            sig,
        })
    )
);

pub fn gen_lease_set<'a>(
    input: (&'a mut [u8], usize),
    ls: &LeaseSet,
) -> Result<(&'a mut [u8], usize), GenError> {
    #[cfg_attr(rustfmt, rustfmt_skip)]
    do_gen!(
        input,
        gen_destination(&ls.dest) >>
        gen_public_key(&ls.enc_key) >>
        gen_signing_key(&ls.sig_key) >>
        gen_be_u8!(ls.leases.len() as u8) >>
        gen_many!(&ls.leases, gen_lease) >>
        gen_signature(&ls.sig)
    )
}

// RouterAddress

#[cfg_attr(rustfmt, rustfmt_skip)]
named!(
    router_address<RouterAddress>,
    do_parse!(
        cost:            be_u8 >>
        expiration:      i2p_date >>
        transport_style: i2p_string >>
        options:         mapping >>
        (RouterAddress {
            cost,
            expiration,
            transport_style,
            options,
        })
    )
);

fn gen_router_address<'a>(
    input: (&'a mut [u8], usize),
    addr: &RouterAddress,
) -> Result<(&'a mut [u8], usize), GenError> {
    #[cfg_attr(rustfmt, rustfmt_skip)]
    do_gen!(
        input,
        gen_be_u8!(addr.cost) >>
        gen_i2p_date(&addr.expiration) >>
        gen_i2p_string(&addr.transport_style) >>
        gen_mapping(&addr.options)
    )
}

// RouterInfo

named!(pub router_info<RouterInfo>,
    do_parse!(
        router_id: router_identity >>
        published: i2p_date >>
        addresses: length_count!(be_u8, router_address) >>
        peers:     length_count!(be_u8, hash) >>
        options:   mapping >>
        signature: call!(signature, &router_id.signing_key.sig_type()) >>
        (RouterInfo {
            router_id,
            published,
            addresses,
            peers,
            options,
            signature: Some(signature),
        })
    )
);

pub fn gen_router_info_minus_sig<'a>(
    input: (&'a mut [u8], usize),
    ri: &RouterInfo,
) -> Result<(&'a mut [u8], usize), GenError> {
    #[cfg_attr(rustfmt, rustfmt_skip)]
    do_gen!(
        input,
        gen_router_identity(&ri.router_id) >>
        gen_i2p_date(&ri.published) >>
        gen_be_u8!(ri.addresses.len() as u8) >>
        gen_many_ref!(&ri.addresses, gen_router_address) >>
        gen_be_u8!(ri.peers.len() as u8) >>
        gen_many_ref!(&ri.peers, gen_hash) >>
        gen_mapping(&ri.options)
    )
}

pub fn gen_router_info<'a>(
    input: (&'a mut [u8], usize),
    ri: &RouterInfo,
) -> Result<(&'a mut [u8], usize), GenError> {
    match &ri.signature {
        &Some(ref s) => do_gen!(input, gen_router_info_minus_sig(&ri) >> gen_signature(s)),
        &None => Err(GenError::CustomError(1)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use nom::HexDisplay;

    #[test]
    fn test_router_info() {
        let data = include_bytes!("../../assets/router.info");
        println!("bytes:\n{}", &data.to_hex(8));
        // Test parsing
        match router_info(data) {
            Ok((_, ri)) => {
                println!("parsed: {:?}", ri);
                assert_eq!(ri.router_id.signing_key.sig_type(), SigType::Ed25519);
                assert_eq!(ri.router_id.certificate.code(), constants::KEY_CERT);
                assert_eq!(ri.published, I2PDate(1505588133655));
                assert_eq!(ri.addresses.len(), 2);
                assert_eq!(ri.peers.len(), 0);
                assert_eq!(
                    ri.options.0[&I2PString(String::from("caps"))],
                    I2PString(String::from("L"))
                );

                // Test generation
                let mut buf: Vec<u8> = Vec::new();
                buf.resize(data.len(), 0);
                match gen_router_info((&mut buf, 0), &ri) {
                    Ok((o, _)) => {
                        println!("generated bytes:\n{}", &o.to_hex(8));
                        assert_eq!(&o[..], &data[..])
                    }
                    Err(e) => panic!("error in gen_router_info: {:?}", e),
                }
            }
            Err(Err::Error(e)) => {
                panic!("error in router_info: {:?}", e);
            }
            Err(Err::Failure(e)) => {
                panic!("failure in router_info: {:?}", e);
            }
            Err(Err::Incomplete(n)) => {
                panic!("incomplete router_info: {:?}", n);
            }
        }
    }
}
