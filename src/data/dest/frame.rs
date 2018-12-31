use cookie_factory::*;
use nom::*;

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

pub fn gen_destination<'a>(
    input: (&'a mut [u8], usize),
    dest: &Destination,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(
        input,
        gen_public_key(&dest.public_key)
            >> gen_cond!(
                dest.padding.is_some(),
                gen_slice!(dest.padding.as_ref().unwrap())
            )
            >> gen_truncated_signing_key(&dest.signing_key)
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
        sig:     call!(signature, dest.signing_key.sig_type()) >>
        (LeaseSet {
            sig_key,
            dest,
            enc_key,
            leases,
            signature: Some(sig),
        })
    )
);

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
