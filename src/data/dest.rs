use std::time::SystemTime;

use super::{cert_and_padding_from_keys, Certificate, Padding};
use crate::crypto::{
    self, elgamal, PrivateKey, PublicKey, Signature, SigningPrivateKey, SigningPublicKey,
};
use crate::data::{Hash, I2PDate, TunnelId};
use crate::util::serialize;

pub(crate) mod frame;

/// A Destination defines a particular endpoint to which messages can be
/// directed for secure delivery.
#[derive(Clone)]
pub struct Destination {
    pub(super) public_key: PublicKey,
    pub(super) padding: Option<Padding>,
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
        serialize(|input| frame::gen_destination(input, self))
    }

    pub fn hash(&self) -> Hash {
        Hash::digest(&self.to_bytes()[..])
    }
}

/// Key material for a Destination.
pub struct DestinationSecretKeys {
    pub dest: Destination,
    private_key: PrivateKey,
    pub signing_private_key: SigningPrivateKey,
}

impl DestinationSecretKeys {
    pub fn new() -> Self {
        let (private_key, public_key) = elgamal::KeyPairGenerator::generate();
        let signing_private_key = SigningPrivateKey::new();
        let signing_key = SigningPublicKey::from_secret(&signing_private_key).unwrap();
        DestinationSecretKeys {
            dest: Destination::from_keys(public_key, signing_key),
            private_key,
            signing_private_key,
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

impl Lease {
    pub fn new(tunnel_gw: Hash, tid: TunnelId, end_date: I2PDate) -> Self {
        Lease {
            tunnel_gw,
            tid,
            end_date,
        }
    }
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
    pub(super) signature: Option<Signature>,
}

impl LeaseSet {
    pub fn new(dest: Destination, enc_key: PublicKey, sig_key: SigningPublicKey) -> Self {
        LeaseSet {
            dest,
            enc_key,
            sig_key,
            leases: vec![],
            signature: None,
        }
    }

    pub fn add_lease(&mut self, lease: Lease) {
        self.leases.push(lease);
    }

    pub fn sign(&mut self, sk: &SigningPrivateKey) -> Result<(), crypto::Error> {
        let sig_bytes = serialize(|input| frame::gen_lease_set_minus_sig(input, self));
        self.signature = Some(sk.sign(&sig_bytes)?);
        Ok(())
    }

    pub fn verify(&self) -> Result<(), crypto::Error> {
        match self.signature.as_ref() {
            Some(s) => {
                let sig_bytes = serialize(|input| frame::gen_lease_set_minus_sig(input, self));
                self.dest.signing_key.verify(&sig_bytes, s)
            }
            None => Err(crypto::Error::NoSignature),
        }
    }

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
    use std::time::SystemTime;

    use super::{Destination, DestinationSecretKeys, Lease, LeaseSet};
    use crate::{
        crypto::{
            self, elgamal::KeyPairGenerator, PublicKey, SigType, SigningPrivateKey,
            SigningPublicKey,
        },
        data::{Certificate, Hash, I2PDate, TunnelId},
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

    #[test]
    fn ls_sign() {
        let dsk = DestinationSecretKeys::new();
        let dest = dsk.dest;
        let key = dest.hash();

        let (_, enc_key) = KeyPairGenerator::generate();
        let sig_privkey = SigningPrivateKey::new();
        let sig_key = SigningPublicKey::from_secret(&sig_privkey).unwrap();

        let mut ls = LeaseSet::new(dest, enc_key, sig_key);
        let end_date = I2PDate::from_system_time(SystemTime::now());
        for i in 1..3 {
            ls.add_lease(Lease::new(Hash([i; 32]), TunnelId(i.into()), end_date));
        }

        assert_eq!(ls.verify(), Err(crypto::Error::NoSignature));
        ls.sign(&dsk.signing_private_key).unwrap();
        assert_eq!(ls.verify(), Ok(()));
    }
}
