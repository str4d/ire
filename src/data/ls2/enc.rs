//! Encryption mechanism for lease information in the network database.
//!
//! Blinding is used to enforce that only clients with knowledge of the
//! Destination can decrypt the lease information.

use super::{LeaseSet2, MetaLeaseSet2, TransientSigningPublicKey};
use crate::crypto::{Signature, SigningPublicKey};

pub mod auth;
pub(crate) mod frame;

/// The inner payload of an encrypted LS2.
pub enum EncLS2Payload {
    LS2(LeaseSet2),
    MetaLS2(MetaLeaseSet2),
}

/// Client authentication layer inside an encrypted LS2.
#[derive(Debug, PartialEq)]
pub(crate) struct EncLS2ClientAuth {
    auth_data: Option<auth::ClientAuthType>,
    inner_ciphertext: Vec<u8>,
}

/// Encrypted and blinded lease information.
pub struct EncryptedLS2 {
    blinded_key: SigningPublicKey,
    created: u32,
    expires: u16,
    transient: Option<TransientSigningPublicKey>,
    outer_ciphertext: Vec<u8>,
    signature: Option<Signature>,
}
