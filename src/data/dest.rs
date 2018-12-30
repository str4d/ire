use cookie_factory::GenError;
use std::iter::repeat;
use std::time::SystemTime;

use super::{cert_and_padding_from_keys, Certificate};
use crate::crypto::{PublicKey, Signature, SigningPublicKey};
use crate::data::{Hash, I2PDate, TunnelId};

pub(crate) mod frame;

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

    pub fn to_bytes(&self) -> Vec<u8> {
        let base_len = 387;
        let mut buf = Vec::with_capacity(base_len);
        buf.extend(repeat(0).take(base_len));
        loop {
            match frame::gen_destination((&mut buf[..], 0), self).map(|tup| tup.1) {
                Ok(sz) => {
                    buf.truncate(sz);
                    return buf;
                }
                Err(e) => match e {
                    GenError::BufferTooSmall(sz) => {
                        buf.extend(repeat(0).take(sz - base_len));
                    }
                    _ => panic!("Couldn't serialize Destination"),
                },
            }
        }
    }

    pub fn hash(&self) -> Hash {
        Hash::digest(&self.to_bytes()[..])
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

#[cfg(test)]
mod tests {
    use super::Destination;
    use crate::{
        crypto::{PublicKey, SigType, SigningPublicKey},
        data::{Certificate, Hash},
    };

    #[test]
    fn dest_hash() {
        let dest = Destination {
            public_key: PublicKey([1; 256]),
            padding: None,
            signing_key: SigningPublicKey::from_bytes(SigType::DsaSha1, &[2; 128][..]).unwrap(),
            certificate: Certificate::Null,
        };
        assert_eq!(
            dest.hash(),
            Hash([
                0xb1, 0x79, 0x22, 0x5a, 0xdc, 0x23, 0xcf, 0xba, 0x8d, 0xa5, 0xdf, 0xfd, 0x0b, 0x24,
                0xca, 0xc1, 0xfd, 0x7a, 0x69, 0xe0, 0x20, 0x35, 0x45, 0xf6, 0x3c, 0xd8, 0xe1, 0x4d,
                0x10, 0x99, 0xc4, 0xd8
            ])
        );
    }
}
