use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{Destination, Hash, Mapping, TunnelId};
use crate::constants::{NETDB_STORE_LS, NETDB_STORE_LS2, NETDB_STORE_META_LS2};
use crate::crypto::{self, CryptoKey, Signature, SigningPrivateKey, SigningPublicKey};
use crate::util::serialize;

#[allow(clippy::needless_pass_by_value)]
pub(crate) mod frame;

/// A transient signing key that has been authorized by another signing key to
/// sign on its behalf. Used when a keyholder wants to keep their actual signing
/// key offline.
#[derive(Clone, Debug, PartialEq)]
pub struct TransientSigningPublicKey {
    expires: u32,
    pubkey: SigningPublicKey,
    signature: Signature,
}

impl TransientSigningPublicKey {
    /// Create a new TransientSigningPublicKey (and its corresponding private key),
    /// bound to the given parent SigningPrivateKey.
    pub fn new(parent: &SigningPrivateKey, expires: u32) -> (Self, SigningPrivateKey) {
        let privkey = SigningPrivateKey::new();
        let mut transient = TransientSigningPublicKey {
            expires,
            pubkey: SigningPublicKey::from_secret(&privkey).unwrap(),
            signature: Signature::Unsupported(vec![]),
        };

        let transient_bytes =
            serialize(|input| frame::gen_transient_key_sig_bytes(input, &transient));
        transient.signature = parent.sign(&transient_bytes).unwrap();

        (transient, privkey)
    }

    /// Verify the TransientSigningPublicKey against the given parent SigningPublicKey.
    pub fn verify(&self, parent: &SigningPublicKey) -> Result<(), crypto::Error> {
        let transient_bytes = serialize(|input| frame::gen_transient_key_sig_bytes(input, self));
        parent.verify(&transient_bytes, &self.signature)
    }
}

/// The standard header used for LeaseSet2 and MetaLeaseSet2.
#[derive(Clone, Debug)]
pub struct LeaseSet2Header {
    pub dest: Destination,
    created: u32,
    expires: u16,
    transient: Option<TransientSigningPublicKey>,
    published: bool,
}

impl LeaseSet2Header {
    // Helper to check that a SigningPrivateKey matches this header.
    fn check_signing_private_key(&self, sk: &SigningPrivateKey) -> Result<(), crypto::Error> {
        let vk = SigningPublicKey::from_secret(sk)?;
        if &vk
            == if let Some(transient) = &self.transient {
                &transient.pubkey
            } else {
                &self.dest.signing_key
            }
        {
            Ok(())
        } else {
            Err(crypto::Error::InvalidKey)
        }
    }

    /// Helper for verifying a structure containing a LeaseSet2Header.
    fn verify(&self, sig_bytes: &[u8], signature: &Signature) -> Result<(), crypto::Error> {
        if let Some(transient) = &self.transient {
            // Verify the transient pubkey
            transient.verify(&self.dest.signing_key)?;

            // Transient key must have an expiry before the LeaseSet2 was created
            if transient.expires >= self.created {
                return Err(crypto::Error::KeyExpired);
            }

            // Now verify the LeaseSet2 signature
            transient.pubkey.verify(&sig_bytes, signature)
        } else {
            self.dest.signing_key.verify(&sig_bytes, signature)
        }
    }

    /// Returns true if the LeaseSet2Header has not expired.
    fn is_current(&self) -> bool {
        // Expiry time is the earliest of the transient key expiry time (if present) and
        // the header expiry time.
        let header_expires = u64::from(self.created) + u64::from(self.expires);
        let expires = if let Some(transient) = &self.transient {
            std::cmp::min(header_expires, u64::from(transient.expires))
        } else {
            header_expires
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::new(0, 0))
            .as_secs();

        now < expires
    }
}

/// Defines the authorization for a particular tunnel to receive messages
/// targeting a Destination. Semantically identical to a Lease, except that
/// it has a 4-byte expiration (seconds since the epoch).
#[derive(Clone, Debug)]
pub struct Lease2 {
    tunnel_gw: Hash,
    tid: TunnelId,
    end_date: u32,
}

impl Lease2 {
    pub fn new(tunnel_gw: Hash, tid: TunnelId, end_date: u32) -> Self {
        Lease2 {
            tunnel_gw,
            tid,
            end_date,
        }
    }
}

/// A v2 LeaseSet. Contains a list of supported end-to-end cryptography types
/// (with corresponding key material).
#[derive(Clone, Debug)]
pub struct LeaseSet2 {
    pub header: LeaseSet2Header,
    properties: Mapping,
    enc_keys: Vec<CryptoKey>,
    leases: Vec<Lease2>,
    signature: Option<Signature>,
}

impl LeaseSet2 {
    /// Create a new LeaseSet2 for the given Destination. If transient is set,
    /// the LeaseSet2 is created with offline keys.
    pub fn new(
        dest: Destination,
        created: u32,
        expires: u16,
        transient: Option<TransientSigningPublicKey>,
    ) -> Self {
        LeaseSet2 {
            header: LeaseSet2Header {
                dest,
                created,
                expires,
                transient,
                published: false,
            },
            properties: Mapping::default(),
            enc_keys: vec![],
            leases: vec![],
            signature: None,
        }
    }

    /// Add an encryption key to the LeaseSet2, advertising that peers may use the
    /// corresponding CryptoType to communicate with this Destination.
    pub fn add_key(&mut self, enc_key: CryptoKey) {
        self.enc_keys.push(enc_key);
    }

    /// Add a lease to the LeaseSet2.
    pub fn add_lease(&mut self, lease: Lease2) {
        self.leases.push(lease);
    }

    /// Sign the LeaseSet2. The SigningPrivateKey must match the transient key if set,
    /// otherwise it must match the Destination.
    pub fn sign(&mut self, sk: &SigningPrivateKey) -> Result<(), crypto::Error> {
        // Check that the SigningPrivateKey is correct
        self.header.check_signing_private_key(sk)?;

        // Create the signature
        let sig_bytes = serialize(|input| frame::gen_lease_set_2_sig_bytes(input, self));
        self.signature = Some(sk.sign(&sig_bytes)?);
        Ok(())
    }

    /// Verify the LeaseSet2.
    pub fn verify(&self) -> Result<(), crypto::Error> {
        match self.signature.as_ref() {
            Some(s) => {
                let sig_bytes = serialize(|input| frame::gen_lease_set_2_sig_bytes(input, self));
                self.header.verify(&sig_bytes, s)
            }
            None => Err(crypto::Error::NoSignature),
        }
    }

    /// Returns true if the LeaseSet2 has not expired.
    pub fn is_current(&self) -> bool {
        self.header.is_current()
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum MetaEntryType {
    Unknown,
    LeaseSet,
    LeaseSet2,
    MetaLeaseSet2,
}

impl MetaEntryType {
    fn from_type(entry_type: u8) -> Self {
        match entry_type {
            NETDB_STORE_LS => MetaEntryType::LeaseSet,
            NETDB_STORE_LS2 => MetaEntryType::LeaseSet2,
            NETDB_STORE_META_LS2 => MetaEntryType::MetaLeaseSet2,
            _ => MetaEntryType::Unknown,
        }
    }

    fn to_type(self) -> u8 {
        match self {
            MetaEntryType::Unknown => 0,
            MetaEntryType::LeaseSet => NETDB_STORE_LS,
            MetaEntryType::LeaseSet2 => NETDB_STORE_LS2,
            MetaEntryType::MetaLeaseSet2 => NETDB_STORE_META_LS2,
        }
    }
}

/// A reference to another LeaseSet, LeaseSet2, or MetaLeaseSet2.
#[derive(Clone)]
pub struct MetaEntry {
    hash: Hash,
    entry_type: MetaEntryType,
    cost: u8,
    expires: u32,
}

/// The root of a tree, the leaves of which are LeaseSet or LeaseSet2.
#[derive(Clone)]
pub struct MetaLeaseSet2 {
    header: LeaseSet2Header,
    properties: Mapping,
    entries: Vec<MetaEntry>,
    revocations: Vec<Hash>,
    signature: Option<Signature>,
}

impl MetaLeaseSet2 {
    /// Create a new MetaLeaseSet2 for the given Destination. If transient is set,
    /// the MetaLeaseSet2 is created with offline keys.
    pub fn new(
        dest: Destination,
        created: u32,
        expires: u16,
        transient: Option<TransientSigningPublicKey>,
    ) -> Self {
        MetaLeaseSet2 {
            header: LeaseSet2Header {
                dest,
                created,
                expires,
                transient,
                published: false,
            },
            properties: Mapping::default(),
            entries: vec![],
            revocations: vec![],
            signature: None,
        }
    }

    /// Add an entry to the MetaLeaseSet2.
    pub fn add_entry(&mut self, entry: MetaEntry) {
        self.entries.push(entry);
    }

    /// Add a revocation to the MetaLeaseSet2.
    pub fn add_revocation(&mut self, revocation: Hash) {
        self.revocations.push(revocation);
    }

    /// Sign the MetaLeaseSet2. The SigningPrivateKey must match the transient key if set,
    /// otherwise it must match the Destination.
    pub fn sign(&mut self, sk: &SigningPrivateKey) -> Result<(), crypto::Error> {
        // Check that the SigningPrivateKey is correct
        self.header.check_signing_private_key(sk)?;

        // Create the signature
        let sig_bytes = serialize(|input| frame::gen_meta_ls2_sig_bytes(input, self));
        self.signature = Some(sk.sign(&sig_bytes)?);
        Ok(())
    }

    /// Verify the MetaLeaseSet2.
    pub fn verify(&self) -> Result<(), crypto::Error> {
        match self.signature.as_ref() {
            Some(s) => {
                let sig_bytes = serialize(|input| frame::gen_meta_ls2_sig_bytes(input, self));
                self.header.verify(&sig_bytes, s)
            }
            None => Err(crypto::Error::NoSignature),
        }
    }

    /// Returns true if the MetaLeaseSet2 has not expired.
    pub fn is_current(&self) -> bool {
        self.header.is_current()
    }
}

#[cfg(test)]
mod tests {
    use super::{LeaseSet2, MetaLeaseSet2, TransientSigningPublicKey};
    use crate::{
        crypto::{self, SigningPrivateKey},
        data::dest::DestinationSecretKeys,
    };

    #[test]
    fn ls2_sign_verify() {
        let dsk = DestinationSecretKeys::new();
        let dest = dsk.dest;
        let mut ls2 = LeaseSet2::new(dest, 0, 0, None);
        ls2.sign(&dsk.signing_private_key).unwrap();
        assert_eq!(ls2.verify(), Ok(()));
    }

    #[test]
    fn ls2_sign_invalid_key() {
        let dsk = DestinationSecretKeys::new();
        let dest = dsk.dest;
        let mut ls2 = LeaseSet2::new(dest, 0, 0, None);
        assert_eq!(
            ls2.sign(&SigningPrivateKey::new()),
            Err(crypto::Error::InvalidKey)
        );
    }

    #[test]
    fn transient_ls2_sign_verify() {
        let dsk = DestinationSecretKeys::new();
        let dest = dsk.dest;
        let (transient, t_sk) = TransientSigningPublicKey::new(&dsk.signing_private_key, 10);
        let mut ls2 = LeaseSet2::new(dest, 20, 0, Some(transient));
        ls2.sign(&t_sk).unwrap();
        assert_eq!(ls2.verify(), Ok(()));
    }

    #[test]
    fn transient_ls2_sign_invalid_key() {
        let dsk = DestinationSecretKeys::new();
        let dest = dsk.dest;
        let (transient, _) = TransientSigningPublicKey::new(&dsk.signing_private_key, 10);
        let mut ls2 = LeaseSet2::new(dest, 20, 0, Some(transient));
        assert_eq!(
            ls2.sign(&SigningPrivateKey::new()),
            Err(crypto::Error::InvalidKey)
        );
    }

    #[test]
    fn transient_ls2_sign_expired() {
        let dsk = DestinationSecretKeys::new();
        let dest = dsk.dest;
        let (transient, t_sk) = TransientSigningPublicKey::new(&dsk.signing_private_key, 10);
        let mut ls2 = LeaseSet2::new(dest, 10, 0, Some(transient));
        ls2.sign(&t_sk).unwrap();
        assert_eq!(ls2.verify(), Err(crypto::Error::KeyExpired));
    }

    #[test]
    fn meta_ls2_sign_verify() {
        let dsk = DestinationSecretKeys::new();
        let dest = dsk.dest;
        let mut meta_ls2 = MetaLeaseSet2::new(dest, 0, 0, None);
        meta_ls2.sign(&dsk.signing_private_key).unwrap();
        assert_eq!(meta_ls2.verify(), Ok(()));
    }

    #[test]
    fn meta_ls2_sign_invalid_key() {
        let dsk = DestinationSecretKeys::new();
        let dest = dsk.dest;
        let mut meta_ls2 = MetaLeaseSet2::new(dest, 0, 0, None);
        assert_eq!(
            meta_ls2.sign(&SigningPrivateKey::new()),
            Err(crypto::Error::InvalidKey)
        );
    }

    #[test]
    fn transient_meta_ls2_sign_verify() {
        let dsk = DestinationSecretKeys::new();
        let dest = dsk.dest;
        let (transient, t_sk) = TransientSigningPublicKey::new(&dsk.signing_private_key, 10);
        let mut meta_ls2 = MetaLeaseSet2::new(dest, 20, 0, Some(transient));
        meta_ls2.sign(&t_sk).unwrap();
        assert_eq!(meta_ls2.verify(), Ok(()));
    }

    #[test]
    fn transient_meta_ls2_sign_invalid_key() {
        let dsk = DestinationSecretKeys::new();
        let dest = dsk.dest;
        let (transient, _) = TransientSigningPublicKey::new(&dsk.signing_private_key, 10);
        let mut meta_ls2 = MetaLeaseSet2::new(dest, 20, 0, Some(transient));
        assert_eq!(
            meta_ls2.sign(&SigningPrivateKey::new()),
            Err(crypto::Error::InvalidKey)
        );
    }

    #[test]
    fn transient_meta_ls2_sign_expired() {
        let dsk = DestinationSecretKeys::new();
        let dest = dsk.dest;
        let (transient, t_sk) = TransientSigningPublicKey::new(&dsk.signing_private_key, 10);
        let mut meta_ls2 = MetaLeaseSet2::new(dest, 10, 0, Some(transient));
        meta_ls2.sign(&t_sk).unwrap();
        assert_eq!(meta_ls2.verify(), Err(crypto::Error::KeyExpired));
    }
}
