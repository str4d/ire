use cookie_factory::*;
use nom::*;

use super::{
    Lease2, LeaseSet2, LeaseSet2Header, MetaEntry, MetaEntryType, MetaLeaseSet2,
    TransientSigningPublicKey,
};
use crate::constants::{NETDB_STORE_LS2, NETDB_STORE_META_LS2};
use crate::crypto::{
    frame::{
        crypto_key, gen_crypto_key, gen_sig_type, gen_signature, gen_signing_key, sig_type,
        signature, signing_key,
    },
    SigType,
};
use crate::data::{
    dest::frame::{destination, gen_destination},
    frame::{gen_hash, gen_mapping, gen_tunnel_id, hash, mapping, tunnel_id},
};

// TransientSigningPublicKey

named_args!(
    pub transient_key(parent_sig_type: SigType)<TransientSigningPublicKey>,
    do_parse!(
        expires: be_u32
            >> sig_type: sig_type
            >> pubkey: call!(signing_key, sig_type)
            >> signature: call!(signature, parent_sig_type)
            >> (TransientSigningPublicKey {
                expires,
                pubkey,
                signature,
            })
    )
);

pub fn gen_transient_key_sig_bytes<'a>(
    input: (&'a mut [u8], usize),
    transient: &TransientSigningPublicKey,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(
        input,
        gen_be_u32!(transient.expires)
            >> gen_sig_type(transient.pubkey.sig_type())
            >> gen_signing_key(&transient.pubkey)
    )
}

pub fn gen_transient_key<'a>(
    input: (&'a mut [u8], usize),
    transient: &TransientSigningPublicKey,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(
        input,
        gen_transient_key_sig_bytes(transient) >> gen_signature(&transient.signature)
    )
}

// Lease2

named!(
    lease2<Lease2>,
    do_parse!(
        tunnel_gw: hash
            >> tid: tunnel_id
            >> end_date: be_u32
            >> (Lease2 {
                tunnel_gw,
                tid,
                end_date,
            })
    )
);

fn gen_lease2<'a>(
    input: (&'a mut [u8], usize),
    lease: &Lease2,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(
        input,
        gen_hash(&lease.tunnel_gw) >> gen_tunnel_id(&lease.tid) >> gen_be_u32!(lease.end_date)
    )
}

// LeaseSet2 standard header

struct LS2Flags {
    offline: bool,
    unpublished: bool,
}

named!(
    lease_set_2_header<LeaseSet2Header>,
    do_parse!(
        dest: destination
            >> created: be_u32
            >> expires: be_u16
            >> flags:
                bits!(do_parse!(
                    take_bits!(u16, 14)
                        >> unpublished: take_bits!(u8, 1)
                        >> offline: take_bits!(u8, 1)
                        >> (LS2Flags {
                            offline: offline > 0,
                            unpublished: unpublished > 0,
                        })
                ))
            >> transient:
                cond!(
                    flags.offline,
                    call!(transient_key, dest.signing_key.sig_type())
                )
            >> (LeaseSet2Header {
                dest,
                created,
                expires,
                transient,
                published: !flags.unpublished,
            })
    )
);

pub fn gen_lease_set_2_header<'a>(
    input: (&'a mut [u8], usize),
    header: &LeaseSet2Header,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(
        input,
        gen_destination(&header.dest)
            >> gen_be_u32!(header.created)
            >> gen_be_u16!(header.expires)
            >> gen_be_u16!({
                let mut x: u16 = 0;
                if header.transient.is_some() {
                    x |= 0b01;
                }
                if !header.published {
                    x |= 0b10;
                }
                x
            })
            >> gen_cond!(
                header.transient.is_some(),
                do_gen!(gen_transient_key(header.transient.as_ref().unwrap()))
            )
    )
}

// LeaseSet2

named!(
    pub lease_set_2<LeaseSet2>,
    do_parse!(
        header: lease_set_2_header
            >> properties: mapping
            >> enc_keys: length_count!(be_u8, crypto_key)
            >> leases: length_count!(be_u8, lease2)
            >> signature:
                call!(
                    signature,
                    if let Some(transient) = header.transient.as_ref() {
                        transient.pubkey.sig_type()
                    } else {
                        header.dest.signing_key.sig_type()
                    }
                )
            >> (LeaseSet2 {
                header,
                properties,
                enc_keys,
                leases,
                signature: Some(signature),
            })
    )
);

pub fn gen_lease_set_2_minus_sig<'a>(
    input: (&'a mut [u8], usize),
    ls2: &LeaseSet2,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(
        input,
        gen_lease_set_2_header(&ls2.header)
            >> gen_mapping(&ls2.properties)
            >> gen_be_u8!(ls2.enc_keys.len() as u8)
            >> gen_many!(&ls2.enc_keys, gen_crypto_key)
            >> gen_be_u8!(ls2.leases.len() as u8)
            >> gen_many!(&ls2.leases, gen_lease2)
    )
}

pub fn gen_lease_set_2_sig_bytes<'a>(
    input: (&'a mut [u8], usize),
    ls2: &LeaseSet2,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(
        input,
        gen_be_u8!(NETDB_STORE_LS2) >> gen_lease_set_2_minus_sig(ls2)
    )
}

pub fn gen_lease_set_2<'a>(
    input: (&'a mut [u8], usize),
    ls2: &LeaseSet2,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(
        input,
        gen_lease_set_2_minus_sig(ls2) >> gen_signature(ls2.signature.as_ref().unwrap())
    )
}

// MetaEntry

named!(
    meta_entry<MetaEntry>,
    do_parse!(
        hash: hash
            >> be_u16
            >> entry_type: be_u8
            >> cost: be_u8
            >> expires: be_u32
            >> (MetaEntry {
                hash,
                entry_type: MetaEntryType::from_type(entry_type),
                cost,
                expires,
            })
    )
);

pub fn gen_meta_entry<'a>(
    input: (&'a mut [u8], usize),
    entry: &MetaEntry,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(
        input,
        gen_hash(&entry.hash)
            >> gen_be_u16!(0)
            >> gen_be_u8!(entry.entry_type.to_type())
            >> gen_be_u8!(entry.cost)
            >> gen_be_u32!(entry.expires)
    )
}

// MetaLeaseSet2

named!(
    pub meta_ls2<MetaLeaseSet2>,
    do_parse!(
        header: lease_set_2_header
            >> properties: mapping
            >> entries: length_count!(be_u8, meta_entry)
            >> revocations: length_count!(be_u8, hash)
            >> signature:
                call!(
                    signature,
                    if let Some(transient) = header.transient.as_ref() {
                        transient.pubkey.sig_type()
                    } else {
                        header.dest.signing_key.sig_type()
                    }
                )
            >> (MetaLeaseSet2 {
                header,
                properties,
                entries,
                revocations,
                signature: Some(signature),
            })
    )
);

pub fn gen_meta_ls2_minus_sig<'a>(
    input: (&'a mut [u8], usize),
    meta_ls2: &MetaLeaseSet2,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(
        input,
        gen_lease_set_2_header(&meta_ls2.header)
            >> gen_mapping(&meta_ls2.properties)
            >> gen_be_u8!(meta_ls2.entries.len() as u8)
            >> gen_many!(&meta_ls2.entries, gen_meta_entry)
            >> gen_be_u8!(meta_ls2.revocations.len() as u8)
            >> gen_many!(&meta_ls2.revocations, gen_hash)
    )
}

pub fn gen_meta_ls2_sig_bytes<'a>(
    input: (&'a mut [u8], usize),
    meta_ls2: &MetaLeaseSet2,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(
        input,
        gen_be_u8!(NETDB_STORE_META_LS2) >> gen_meta_ls2_minus_sig(meta_ls2)
    )
}

pub fn gen_meta_ls2<'a>(
    input: (&'a mut [u8], usize),
    meta_ls2: &MetaLeaseSet2,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(
        input,
        gen_meta_ls2_minus_sig(meta_ls2) >> gen_signature(meta_ls2.signature.as_ref().unwrap())
    )
}
