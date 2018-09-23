//! Implementation of I2P's ElGamal public-key encryption scheme over the
//! 2048-bit MODP DH group.
//!
//! Original implementation in Java I2P was based on algorithms 8.17 and 8.18
//! specified in section 8.4.1 of the Handbook of Applied Cryptography.

use num_bigint::{BigUint, RandBigInt};
use num_traits::Zero;
use rand::OsRng;

use super::{math::rectify, PrivateKey, PublicKey};
use constants::{ELGAMAL_G, ELGAMAL_P, ELGAMAL_PM2};

fn gen_gamma_k() -> (BigUint, BigUint) {
    let mut rng = OsRng::new().expect("should be able to construct RNG");

    // Select a random integer k, 1 <= k <= p - 2
    let k = loop {
        let k = rng.gen_biguint(2048);
        if !k.is_zero() && k <= *ELGAMAL_PM2 {
            break k;
        }
    };

    // γ = α^k mod p
    let gamma = ELGAMAL_G.modpow(&k, &ELGAMAL_P);

    (k, gamma)
}

/// Generates ElGamal keypairs.
pub struct KeyPairGenerator;

impl KeyPairGenerator {
    /// ElGamal key generation, following algorithm 8.17.
    pub fn generate() -> (PrivateKey, PublicKey) {
        // Select a random integer a, 1 <= a <= p - 2
        // Public key is α^a mod p
        let (a, alpha_a) = gen_gamma_k();

        let priv_key = {
            let buf = rectify(&a, 256);
            let mut x = [0u8; 256];
            x.copy_from_slice(&buf[..]);
            PrivateKey(x)
        };

        let pub_key = {
            let buf = rectify(&alpha_a, 256);
            let mut x = [0u8; 256];
            x.copy_from_slice(&buf[..]);
            PublicKey(x)
        };

        (priv_key, pub_key)
    }
}
