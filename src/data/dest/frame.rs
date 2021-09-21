use cookie_factory::*;
use nom::*;
use nom::{
    bytes::streaming::take,
    combinator::{map, map_res},
    multi::length_count,
    number::streaming::be_u8,
    sequence::{pair, tuple},
};

use super::{Destination, Lease, LeaseSet};
use crate::constants;
use crate::crypto::frame::{
    gen_public_key, gen_signature, gen_signing_key, public_key, signature, signing_key,
};
use crate::data::frame::{
    certificate, gen_certificate, gen_hash, gen_i2p_date, gen_truncated_signing_key, gen_tunnel_id,
    hash, i2p_date, keycert_padding, split_signing_key, tunnel_id,
};

// Destination

fn destination(i: &[u8]) -> IResult<&[u8], Destination> {
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
            .map(|signing_key| Destination {
                public_key,
                padding,
                signing_key,
                certificate,
            })
        },
    )(i)
}

pub fn gen_destination<'a>(
    input: (&'a mut [u8], usize),
    dest: &Destination,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(
        input,
        gen_public_key(&dest.public_key)
            >> gen_cond!(
                dest.padding.is_some(),
                gen_slice!(dest.padding.as_ref().unwrap().0)
            )
            >> gen_truncated_signing_key(&dest.signing_key)
            >> gen_certificate(&dest.certificate)
    )
}

// Lease

fn lease(i: &[u8]) -> IResult<&[u8], Lease> {
    map(
        tuple((hash, tunnel_id, i2p_date)),
        |(tunnel_gw, tid, end_date)| Lease {
            tunnel_gw,
            tid,
            end_date,
        },
    )(i)
}

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

pub fn lease_set(i: &[u8]) -> IResult<&[u8], LeaseSet> {
    let (i, dest) = destination(i)?;
    let (i, (enc_key, sig_key, leases, sig)) = tuple((
        public_key,
        signing_key(dest.signing_key.sig_type()),
        length_count(be_u8, lease),
        signature(dest.signing_key.sig_type()),
    ))(i)?;
    Ok((
        i,
        LeaseSet {
            sig_key,
            dest,
            enc_key,
            leases,
            signature: Some(sig),
        },
    ))
}

pub fn gen_lease_set_minus_sig<'a>(
    input: (&'a mut [u8], usize),
    ls: &LeaseSet,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(
        input,
        gen_destination(&ls.dest)
            >> gen_public_key(&ls.enc_key)
            >> gen_signing_key(&ls.sig_key)
            >> gen_be_u8!(ls.leases.len() as u8)
            >> gen_many!(&ls.leases, gen_lease)
    )
}

pub fn gen_lease_set<'a>(
    input: (&'a mut [u8], usize),
    ls: &LeaseSet,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(
        input,
        gen_lease_set_minus_sig(ls) >> gen_signature(ls.signature.as_ref().unwrap())
    )
}
