use std::convert::TryInto;

use cookie_factory::*;
use itertools::Itertools;
use nom::{
    bytes::streaming::{tag, take},
    combinator::{complete, map, map_res},
    error::{Error as NomError, ErrorKind},
    multi::{length_count, length_data, length_value, many0},
    number::streaming::{be_u16, be_u32, be_u64, be_u8},
    sequence::{pair, separated_pair, terminated, tuple},
    IResult,
};

use super::*;
use crate::constants;
use crate::crypto::frame::{
    enc_type, gen_enc_type, gen_private_key, gen_public_key, gen_sig_type, gen_signature,
    gen_signing_private_key, private_key, public_key, sig_type, signature, signing_private_key,
};

//
// Simple data types
//

pub fn hash(i: &[u8]) -> IResult<&[u8], Hash> {
    map(take(32usize), |bytes: &[u8]| {
        Hash::from_bytes(bytes.try_into().unwrap())
    })(i)
}
pub fn gen_hash<'a>(
    input: (&'a mut [u8], usize),
    h: &Hash,
) -> Result<(&'a mut [u8], usize), GenError> {
    gen_slice!(input, h.0)
}

pub fn i2p_date(i: &[u8]) -> IResult<&[u8], I2PDate> {
    map(be_u64, I2PDate)(i)
}
pub fn gen_i2p_date<'a>(
    input: (&'a mut [u8], usize),
    date: &I2PDate,
) -> Result<(&'a mut [u8], usize), GenError> {
    gen_be_u64!(input, date.0)
}
pub fn short_expiry(i: &[u8]) -> IResult<&[u8], I2PDate> {
    map(be_u32, |seconds| I2PDate(u64::from(seconds) * 1_000))(i)
}
pub fn gen_short_expiry<'a>(
    input: (&'a mut [u8], usize),
    date: &I2PDate,
) -> Result<(&'a mut [u8], usize), GenError> {
    gen_be_u32!(input, date.0 / 1_000)
}

pub fn i2p_string(i: &[u8]) -> IResult<&[u8], I2PString> {
    map_res(length_data(be_u8), |s: &[u8]| {
        String::from_utf8(s.to_vec()).map(I2PString)
    })(i)
}
pub fn gen_i2p_string<'a>(
    input: (&'a mut [u8], usize),
    s: &I2PString,
) -> Result<(&'a mut [u8], usize), GenError> {
    let buf = s.0.as_bytes();
    do_gen!(input, gen_be_u8!(buf.len() as u8) >> gen_slice!(buf))
}

pub fn mapping(i: &[u8]) -> IResult<&[u8], Mapping> {
    map(
        length_value(
            be_u16,
            many0(complete(terminated(
                separated_pair(i2p_string, tag("="), i2p_string),
                tag(";"),
            ))),
        ),
        |pairs| Mapping(pairs.into_iter().collect()),
    )(i)
}
pub fn gen_mapping_pair<'a>(
    input: (&'a mut [u8], usize),
    pair: (&I2PString, &I2PString),
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(
        input,
        gen_i2p_string(pair.0) >> gen_slice!(b"=") >> gen_i2p_string(pair.1) >> gen_slice!(b";")
    )
}
#[rustfmt::skip]
pub fn gen_mapping<'a>(
    input: (&'a mut [u8], usize),
    m: &Mapping,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(
        input,
        size:  gen_skip!(2) >>
        // Some structures require the Mapping be sorted, so just sort them all
        start: gen_many!(m.0.iter().sorted(), gen_mapping_pair) >>
        end:   gen_at_offset!(size, gen_be_u16!(end - start))
    )
}

pub fn session_tag(i: &[u8]) -> IResult<&[u8], SessionTag> {
    map(take(32usize), |t: &[u8]| {
        SessionTag::from_bytes(t.try_into().unwrap())
    })(i)
}
pub fn gen_session_tag<'a>(
    input: (&'a mut [u8], usize),
    t: &SessionTag,
) -> Result<(&'a mut [u8], usize), GenError> {
    gen_slice!(input, t.0)
}

pub fn tunnel_id(i: &[u8]) -> IResult<&[u8], TunnelId> {
    map(be_u32, TunnelId)(i)
}
pub fn gen_tunnel_id<'a>(
    input: (&'a mut [u8], usize),
    tid: &TunnelId,
) -> Result<(&'a mut [u8], usize), GenError> {
    gen_be_u32!(input, tid.0)
}

// SigningPublicKey

pub(crate) fn split_signing_key(
    base_data: &[u8; constants::KEYCERT_SIGKEY_BYTES],
    cert: &Certificate,
) -> Result<SigningPublicKey, crypto::Error> {
    match cert {
        Certificate::Key(kc) => {
            if kc.sig_type.extra_data_len(kc.enc_type) > 0 {
                let mut data = Vec::from(&base_data[..]);
                data.extend(&kc.sig_data);
                SigningPublicKey::from_bytes(kc.sig_type, &data)
            } else {
                let pad = kc.sig_type.pad_len(kc.enc_type);
                SigningPublicKey::from_bytes(kc.sig_type, &base_data[pad..])
            }
        }
        _ => SigningPublicKey::from_bytes(SigType::DsaSha1, &base_data[..]),
    }
}

pub(crate) fn gen_truncated_signing_key<'a>(
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

pub(crate) fn keycert_padding(base_data: &[u8; 128], cert: &Certificate) -> Option<Padding> {
    let pad_len = match cert {
        Certificate::Key(kc) => Some(kc.sig_type.pad_len(kc.enc_type)),
        _ => None,
    };
    match pad_len {
        Some(pad_len) if pad_len > 0 => Some(Padding(Vec::from(&base_data[0..pad_len]))),
        _ => None,
    }
}

fn key_certificate(i: &[u8]) -> IResult<&[u8], KeyCertificate> {
    let (i, (sig_type, enc_type)) = pair(sig_type, enc_type)(i)?;
    map(
        pair(
            take(sig_type.extra_data_len(enc_type)),
            take(enc_type.extra_data_len(sig_type)),
        ),
        move |(sig_data, enc_data)| KeyCertificate {
            sig_type,
            enc_type,
            sig_data: Vec::from(sig_data),
            enc_data: Vec::from(enc_data),
        },
    )(i)
}

fn gen_key_certificate<'a>(
    input: (&'a mut [u8], usize),
    kc: &KeyCertificate,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(
        input,
        gen_sig_type(kc.sig_type)
            >> gen_enc_type(kc.enc_type)
            >> gen_slice!(&kc.sig_data)
            >> gen_slice!(&kc.enc_data)
    )
}

// Certificate

pub fn certificate(i: &[u8]) -> IResult<&[u8], Certificate> {
    let (i, cert_type) = be_u8(i)?;
    match cert_type {
        constants::NULL_CERT => map(tag(b"\x00\x00"), |_| Certificate::Null)(i),
        constants::HASH_CERT => map(length_data(be_u16), |payload| {
            Certificate::HashCash(Vec::from(payload))
        })(i),
        constants::HIDDEN_CERT => map(tag(b"\x00\x00"), |_| Certificate::Hidden)(i),
        constants::SIGNED_CERT => map(length_data(be_u16), |payload| {
            Certificate::Signed(Vec::from(payload))
        })(i),
        constants::MULTI_CERT => map(length_data(be_u16), |payload| {
            Certificate::Multiple(Vec::from(payload))
        })(i),
        constants::KEY_CERT => map(length_value(be_u16, key_certificate), Certificate::Key)(i),
        _ => Err(nom::Err::Error(NomError::new(i, ErrorKind::Switch))),
    }
}

#[rustfmt::skip]
pub fn gen_certificate<'a>(
    input: (&'a mut [u8], usize),
    cert: &Certificate,
) -> Result<(&'a mut [u8], usize), GenError> {
    match *cert {
        Certificate::Null => do_gen!(
            input,
            gen_be_u8!(constants::NULL_CERT) >>
            gen_be_u16!(0)
        ),
        Certificate::HashCash(ref payload) => do_gen!(
            input,
            gen_be_u8!(constants::HASH_CERT) >>
            gen_be_u16!(payload.len() as u16) >>
            gen_slice!(payload)
        ),
        Certificate::Hidden => do_gen!(
            input,
            gen_be_u8!(constants::HIDDEN_CERT) >>
            gen_be_u16!(0)
        ),
        Certificate::Signed(ref payload) => do_gen!(
            input,
            gen_be_u8!(constants::SIGNED_CERT) >>
            gen_be_u16!(payload.len() as u16) >>
            gen_slice!(payload)
        ),
        Certificate::Multiple(ref payload) => do_gen!(
            input,
            gen_be_u8!(constants::MULTI_CERT) >>
            gen_be_u16!(payload.len() as u16) >>
            gen_slice!(payload)
        ),
        Certificate::Key(ref kc) => do_gen!(
            input,
                   gen_be_u8!(constants::KEY_CERT) >>
            size:  gen_skip!(2) >>
            start: gen_key_certificate(kc) >>
            end:   gen_at_offset!(size, gen_be_u16!(end - start))
        ),
    }
}

// RouterIdentity

pub fn router_identity(i: &[u8]) -> IResult<&[u8], RouterIdentity> {
    map_res(
        tuple((
            public_key,
            take(constants::KEYCERT_SIGKEY_BYTES),
            certificate,
        )),
        |(public_key, signing_data, certificate)| {
            let padding = keycert_padding(
                array_ref![signing_data, 0, constants::KEYCERT_SIGKEY_BYTES],
                &certificate,
            );
            split_signing_key(
                array_ref![signing_data, 0, constants::KEYCERT_SIGKEY_BYTES],
                &certificate,
            )
            .map(|signing_key| RouterIdentity {
                public_key,
                padding,
                signing_key,
                certificate,
            })
        },
    )(i)
}

#[rustfmt::skip]
pub fn gen_router_identity<'a>(
    input: (&'a mut [u8], usize),
    rid: &RouterIdentity,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(
        input,
        gen_public_key(&rid.public_key) >>
        gen_cond!(
            rid.padding.is_some(),
            gen_slice!(rid.padding.as_ref().unwrap().0)
        ) >>
        gen_truncated_signing_key(&rid.signing_key) >>
        gen_certificate(&rid.certificate)
    )
}

// RouterSecretKeys

pub fn router_secret_keys(i: &[u8]) -> IResult<&[u8], RouterSecretKeys> {
    let (i, (rid, private_key)) = pair(router_identity, private_key)(i)?;
    let (i, signing_private_key) = signing_private_key(rid.signing_key.sig_type())(i)?;
    Ok((
        i,
        RouterSecretKeys {
            rid,
            private_key,
            signing_private_key,
        },
    ))
}

pub fn gen_router_secret_keys<'a>(
    input: (&'a mut [u8], usize),
    rsk: &RouterSecretKeys,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(
        input,
        gen_router_identity(&rsk.rid)
            >> gen_private_key(&rsk.private_key)
            >> gen_signing_private_key(&rsk.signing_private_key)
    )
}

// RouterAddress

fn router_address(i: &[u8]) -> IResult<&[u8], RouterAddress> {
    map(
        tuple((be_u8, i2p_date, i2p_string, mapping)),
        |(cost, expiration, transport_style, options)| RouterAddress {
            cost,
            expiration,
            transport_style,
            options,
        },
    )(i)
}

#[rustfmt::skip]
fn gen_router_address<'a>(
    input: (&'a mut [u8], usize),
    addr: &RouterAddress,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(
        input,
        gen_be_u8!(addr.cost) >>
        gen_i2p_date(&addr.expiration) >>
        gen_i2p_string(&addr.transport_style) >>
        gen_mapping(&addr.options)
    )
}

// RouterInfo

pub fn router_info(i: &[u8]) -> IResult<&[u8], RouterInfo> {
    let (i, router_id) = router_identity(i)?;
    let (i, (published, addresses, peers, options, signature)) = tuple((
        i2p_date,
        length_count(be_u8, router_address),
        length_count(be_u8, hash),
        mapping,
        signature(router_id.signing_key.sig_type()),
    ))(i)?;
    Ok((
        i,
        RouterInfo {
            router_id,
            published,
            addresses,
            peers,
            options,
            signature: Some(signature),
        },
    ))
}

#[rustfmt::skip]
pub fn gen_router_info_minus_sig<'a>(
    input: (&'a mut [u8], usize),
    ri: &RouterInfo,
) -> Result<(&'a mut [u8], usize), GenError> {
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
    match ri.signature {
        Some(ref s) => do_gen!(input, gen_router_info_minus_sig(ri) >> gen_signature(s)),
        None => Err(GenError::CustomError(1)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::ROUTER_INFO;

    use nom::{Err, HexDisplay};

    #[test]
    fn test_router_info() {
        let data = ROUTER_INFO;
        println!("bytes:\n{}", &data.to_hex(8));
        // Test parsing
        match router_info(data) {
            Ok((_, ri)) => {
                println!("parsed: {:?}", ri);
                assert_eq!(ri.router_id.signing_key.sig_type(), SigType::Ed25519);
                assert_eq!(ri.router_id.certificate.code(), constants::KEY_CERT);
                assert_eq!(ri.published, I2PDate(1_505_588_133_655));
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
                        assert_eq!(o, &data[..])
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
