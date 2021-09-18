//! Implementation of the DSA signature scheme over I2P's 1024-bit prime field.
//!
//! This implementation is not constant-time.
//!
//! Original implementation in Java I2P was based on algorithms 11.54 and 11.56
//! specified in section 11.5.1 of the Handbook of Applied Cryptography.

use crypto_bigint::U1024;
use rand::{rngs::OsRng, Rng};
use sha1::{Digest, Sha1};

use super::math::rectify;
use crate::constants::{DSA_G, DSA_P, DSA_Q, DSA_QM2, U160};

#[derive(Clone, Debug, PartialEq)]
pub struct DsaSignature {
    rbar: [u8; 20],
    sbar: [u8; 20],
}

/// An I2P DSA 1024 signing key. Private because we only want the implementation
/// for testing purposes; Ire does not support DSA 1024 key material.
struct DsaPrivateKey(U160);

#[derive(Clone, Debug, PartialEq)]
pub struct DsaPublicKey {
    bi: U1024,
    bytes: Vec<u8>,
}

impl DsaSignature {
    pub fn from_bytes(data: &[u8]) -> Result<DsaSignature, super::Error> {
        if data.len() < 40 {
            return Err(super::Error::InvalidSignature);
        }

        let mut rbar = [0u8; 20];
        let mut sbar = [0u8; 20];
        rbar.copy_from_slice(&data[..20]);
        sbar.copy_from_slice(&data[20..40]);

        Ok(DsaSignature { rbar, sbar })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(40);
        data.extend_from_slice(&self.rbar);
        data.extend_from_slice(&self.sbar);
        data
    }
}

impl DsaPrivateKey {
    /// DSA key generation, following algorithm 11.54 4).
    fn new() -> Self {
        let mut rng = OsRng;

        // Select a random integer a, 0 < a < q
        let mut buf = [0; 20];
        loop {
            rng.fill(&mut buf[..]);
            let a = U160::from_be_slice(&buf);
            if !bool::from(a.is_zero()) && a < *DSA_Q {
                return DsaPrivateKey(a);
            }
        }
    }

    /// DSA signature generation, following algorithm 11.56 1).
    fn sign(&self, msg: &[u8]) -> DsaSignature {
        let mut rng = OsRng;

        // Select a random integer k, 0 < k < q
        let mut buf = [0; 20];
        let k = loop {
            rng.fill(&mut buf[..]);
            let k = U160::from_be_slice(&buf);
            if !bool::from(k.is_zero()) && k < *DSA_Q {
                break k;
            }
        };

        // r = (α^k mod p) mod q
        let r = DSA_G.modpow(&k, &DSA_P) % &(*DSA_Q);

        // k^{-1} mod q = k^{q-2} mod q
        let km1 = k.modpow(&DSA_QM2, &DSA_Q);

        // h(m) = SHA1(msg)
        let hm = U160::from_be_slice(&Sha1::digest(msg));

        // s = k^{-1} * (h(m) + a * r) mod q
        let s = km1 * (hm + &self.0 * &r) % &(*DSA_Q);

        let mut rbar = [0u8; 20];
        let mut sbar = [0u8; 20];
        rbar.copy_from_slice(&rectify(&r, 20));
        sbar.copy_from_slice(&rectify(&s, 20));

        DsaSignature { rbar, sbar }
    }
}

impl DsaPublicKey {
    /// DSA key generation, following algorithm 11.54 5).
    fn from_private(sk: &DsaPrivateKey) -> Self {
        // y = α^a mod p
        let y = DSA_G.modpow(&sk.0, &DSA_P);
        let bytes = rectify(&y, 128);
        DsaPublicKey { bi: y, bytes }
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, super::Error> {
        let bi = U1024::from_be_slice(data);
        let bytes = rectify(&bi, 128);
        Ok(DsaPublicKey { bi, bytes })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// DSA signature verification, following algorithm 11.56 2).
    #[allow(clippy::many_single_char_names)]
    pub fn verify(&self, msg: &[u8], sig: &DsaSignature) -> bool {
        let p = &(*DSA_P);
        let q = &(*DSA_Q);

        let r = U160::from_be_slice(&sig.rbar);
        let s = U160::from_be_slice(&sig.sbar);

        // Verify that 0 < r < q and 0 < s < q
        if bool::from(r.is_zero()) || r >= *DSA_Q || bool::from(s.is_zero()) || s >= *DSA_Q {
            return false;
        }

        // w = s^{-1} mod q = s^{q-2} mod q
        let w = s.modpow(&DSA_QM2, q);

        // h(m) = SHA1(msg)
        let hm = U160::from_be_slice(&Sha1::digest(msg));

        // u_1 = w * h(m) mod q
        let u1 = &w * hm % q;

        // u_2 = r * w mod q
        let u2 = &r * &w % q;

        // v = (α^{u_1} * y^{u_2} mod p) mod q
        let v = (DSA_G.modpow(&u1, p) * self.bi.modpow(&u2, p) % p) % q;

        // Accept iff v == r
        v == r
    }
}

#[cfg(test)]
mod tests {
    use super::{DsaPrivateKey, DsaPublicKey, DsaSignature};

    #[test]
    fn random_signatures() {
        for _ in 0..200 {
            let sk = DsaPrivateKey::new();
            let vk = DsaPublicKey::from_private(&sk);

            assert_eq!(DsaPublicKey::from_bytes(vk.as_bytes()).unwrap(), vk);

            let msg1 = b"Foo bar";
            let msg2 = b"Spam eggs";

            let sig1 = sk.sign(msg1);
            let sig2 = sk.sign(msg2);

            assert!(vk.verify(msg1, &sig1));
            assert!(vk.verify(msg2, &sig2));
            assert!(!vk.verify(msg1, &sig2));
            assert!(!vk.verify(msg2, &sig1));

            let encoded1 = sig1.to_bytes();
            let encoded2 = sig2.to_bytes();

            assert_eq!(DsaSignature::from_bytes(&encoded1).unwrap(), sig1);
            assert_eq!(DsaSignature::from_bytes(&encoded2).unwrap(), sig2);
        }
    }
}
