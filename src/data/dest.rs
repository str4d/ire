use std::time::SystemTime;

use super::{cert_and_padding_from_keys, Certificate};
use crate::crypto::{PublicKey, Signature, SigningPublicKey};
use crate::data::{Hash, I2PDate, TunnelId};

/// A Destination defines a particular endpoint to which messages can be
/// directed for secure delivery.
#[derive(Clone)]
pub struct Destination {
    pub(super) public_key: PublicKey,
    pub(super) padding: Option<Vec<u8>>,
    pub(super) signing_key: SigningPublicKey,
    pub(super) certificate: Certificate,
}

impl Destination {
    pub fn from_keys(public_key: PublicKey, signing_key: SigningPublicKey) -> Self {
        let (certificate, padding) = cert_and_padding_from_keys(&public_key, &signing_key);
        Destination {
            public_key,
            padding,
            signing_key,
            certificate,
        }
    }
}

/// Defines the authorization for a particular tunnel to receive messages
/// targeting a Destination.
#[derive(Clone)]
pub struct Lease {
    pub(super) tunnel_gw: Hash,
    pub(super) tid: TunnelId,
    pub(super) end_date: I2PDate,
}

/// Contains all of the currently authorized Leases for a particular Destination,
/// the PublicKey to which garlic messages can be encrypted, and then the
/// SigningPublicKey that can be used to revoke this particular version of the
/// structure.
///
/// The LeaseSet is one of the two structures stored in the network database
/// (the other being RouterInfo), and is keyed under the SHA-256 of the contained
/// Destination.
#[derive(Clone)]
pub struct LeaseSet {
    pub dest: Destination,
    pub(super) enc_key: PublicKey,
    pub(super) sig_key: SigningPublicKey,
    pub(super) leases: Vec<Lease>,
    pub(super) sig: Signature,
}

impl LeaseSet {
    pub fn is_current(&self) -> bool {
        let expiry = self.leases.iter().fold(I2PDate(1), |expiry, lease| {
            if lease.end_date > expiry {
                lease.end_date
            } else {
                expiry
            }
        });
        expiry < I2PDate::from_system_time(SystemTime::now())
    }
}
