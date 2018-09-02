//! Cryptographic types and operations.

use aesti::Aes;
use ed25519_dalek::Keypair as EdKeypair;
use ed25519_dalek::PublicKey as EdPublicKey;
use ed25519_dalek::SecretKey as EdSecretKey;
use ed25519_dalek::Signature as EdSignature;
use ed25519_dalek::SignatureError as EdSignatureError;
use ed25519_dalek::SECRET_KEY_LENGTH as ED_SECRET_KEY_LENGTH;
use nom::Err;
use num::BigUint;
use rand::{self, Rng};
use sha2::Sha512;
use std::fmt;

use constants;

pub(crate) mod frame;
pub(crate) mod math;

pub(crate) const AES_BLOCK_SIZE: usize = 16;

/// Errors that can occur during creation or verification of a Signature.
pub enum SignatureError {
    NoSignature,
    TypeMismatch,
    Ed25519(EdSignatureError),
}

impl From<EdSignatureError> for SignatureError {
    fn from(e: EdSignatureError) -> Self {
        SignatureError::Ed25519(e)
    }
}

/// Various signature algorithms present on the network.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SigType {
    DsaSha1,
    EcdsaSha256P256,
    EcdsaSha384P384,
    EcdsaSha512P521,
    Ed25519,
}

impl SigType {
    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        match frame::sig_type(buf) {
            Ok((_, s)) => Some(s),
            Err(Err::Incomplete(_)) => None,
            Err(Err::Error(_)) | Err(Err::Failure(_)) => panic!("Unsupported SigType"),
        }
    }

    pub fn code(&self) -> u16 {
        match *self {
            SigType::DsaSha1 => constants::DSA_SHA1,
            SigType::EcdsaSha256P256 => constants::ECDSA_SHA256_P256,
            SigType::EcdsaSha384P384 => constants::ECDSA_SHA384_P384,
            SigType::EcdsaSha512P521 => constants::ECDSA_SHA512_P521,
            SigType::Ed25519 => constants::ED25519,
        }
    }

    pub fn pubkey_len(&self) -> u32 {
        match *self {
            SigType::DsaSha1 => 128,
            SigType::EcdsaSha256P256 => 64,
            SigType::EcdsaSha384P384 => 96,
            SigType::EcdsaSha512P521 => 132,
            SigType::Ed25519 => 32,
        }
    }

    pub fn privkey_len(&self) -> u32 {
        match *self {
            SigType::DsaSha1 => 20,
            SigType::EcdsaSha256P256 => 32,
            SigType::EcdsaSha384P384 => 48,
            SigType::EcdsaSha512P521 => 66,
            SigType::Ed25519 => 32,
        }
    }

    pub fn sig_len(&self) -> u32 {
        match *self {
            SigType::DsaSha1 => 40,
            SigType::EcdsaSha256P256 => 64,
            SigType::EcdsaSha384P384 => 96,
            SigType::EcdsaSha512P521 => 132,
            SigType::Ed25519 => 64,
        }
    }

    // Returns a number between 0 and 128
    pub fn pad_len(&self, enc_type: &EncType) -> usize {
        match enc_type {
            &EncType::ElGamal2048 => {
                constants::KEYCERT_SIGKEY_BYTES.saturating_sub(self.pubkey_len() as usize)
            }
        }
    }

    pub fn extra_data_len(&self, enc_type: &EncType) -> usize {
        match enc_type {
            &EncType::ElGamal2048 => {
                (self.pubkey_len() as usize).saturating_sub(constants::KEYCERT_SIGKEY_BYTES)
            }
        }
    }
}

/// Various encryption algorithms present on the network.
#[derive(Clone, Debug, PartialEq)]
pub enum EncType {
    ElGamal2048,
}

impl EncType {
    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        match frame::enc_type(buf) {
            Ok((_, s)) => Some(s),
            Err(Err::Incomplete(_)) => None,
            Err(Err::Error(_)) | Err(Err::Failure(_)) => panic!("Unsupported EncType"),
        }
    }

    pub fn code(&self) -> u16 {
        match *self {
            EncType::ElGamal2048 => constants::ELGAMAL2048,
        }
    }

    pub fn extra_data_len(&self, sig_type: &SigType) -> usize {
        match self {
            &EncType::ElGamal2048 => 0,
        }
    }
}

//
// Key material and signatures
//

/// The public component of an ElGamal encryption keypair. Represents only the
/// exponent, not the primes (which are constants).
pub struct PublicKey(pub [u8; 256]);

impl PublicKey {
    fn from_bytes(buf: &[u8; 256]) -> Self {
        let mut x = [0u8; 256];
        x.copy_from_slice(buf);
        PublicKey(x)
    }

    pub fn from_secret(priv_key: &PrivateKey) -> Self {
        let priv_key_bi = BigUint::from_bytes_be(&priv_key.0[..]);
        let cc = constants::CryptoConstants::new();
        let pub_key_bi = cc.elg_g.modpow(&priv_key_bi, &cc.elg_p);
        let buf = math::rectify(&pub_key_bi, 256);
        let mut x = [0u8; 256];
        x.copy_from_slice(&buf[..]);
        PublicKey(x)
    }
}

impl Clone for PublicKey {
    fn clone(&self) -> Self {
        PublicKey::from_bytes(&self.0)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        self.0[..].fmt(formatter)
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0
            .iter()
            .zip(other.0.iter())
            .fold(true, |acc, (a, b)| acc && (a == b))
    }
}

/// The private component of an ElGamal encryption keypair.
pub struct PrivateKey(pub [u8; 256]);

impl PrivateKey {
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        let mut keydata = [0u8; 256];
        rng.fill(&mut keydata);
        PrivateKey(keydata)
    }

    fn from_bytes(buf: &[u8; 256]) -> Self {
        let mut x = [0u8; 256];
        x.copy_from_slice(buf);
        PrivateKey(x)
    }
}

impl Clone for PrivateKey {
    fn clone(&self) -> Self {
        PrivateKey::from_bytes(&self.0)
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        self.0[..].fmt(formatter)
    }
}

/// The public component of a signature keypair.
#[derive(Clone, Debug, PartialEq)]
pub enum SigningPublicKey {
    DsaSha1,
    EcdsaSha256P256,
    EcdsaSha384P384,
    EcdsaSha512P521,
    Ed25519(EdPublicKey),
}

impl SigningPublicKey {
    pub fn sig_type(&self) -> SigType {
        match self {
            &SigningPublicKey::DsaSha1 => SigType::DsaSha1,
            &SigningPublicKey::EcdsaSha256P256 => SigType::EcdsaSha256P256,
            &SigningPublicKey::EcdsaSha384P384 => SigType::EcdsaSha384P384,
            &SigningPublicKey::EcdsaSha512P521 => SigType::EcdsaSha512P521,
            &SigningPublicKey::Ed25519(_) => SigType::Ed25519,
        }
    }
}

impl SigningPublicKey {
    pub fn from_bytes(sig_type: &SigType, data: &[u8]) -> Result<Self, SignatureError> {
        match sig_type {
            &SigType::DsaSha1 => unimplemented!(),
            &SigType::EcdsaSha256P256 => unimplemented!(),
            &SigType::EcdsaSha384P384 => unimplemented!(),
            &SigType::EcdsaSha512P521 => unimplemented!(),
            &SigType::Ed25519 => Ok(SigningPublicKey::Ed25519(EdPublicKey::from_bytes(data)?)),
        }
    }

    pub fn from_secret(priv_key: &SigningPrivateKey) -> Self {
        match priv_key {
            &SigningPrivateKey::DsaSha1 => unimplemented!(),
            &SigningPrivateKey::EcdsaSha256P256 => unimplemented!(),
            &SigningPrivateKey::EcdsaSha384P384 => unimplemented!(),
            &SigningPrivateKey::EcdsaSha512P521 => unimplemented!(),
            &SigningPrivateKey::Ed25519(ref kp) => SigningPublicKey::Ed25519(kp.public.clone()),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            &SigningPublicKey::DsaSha1 => unimplemented!(),
            &SigningPublicKey::EcdsaSha256P256 => unimplemented!(),
            &SigningPublicKey::EcdsaSha384P384 => unimplemented!(),
            &SigningPublicKey::EcdsaSha512P521 => unimplemented!(),
            &SigningPublicKey::Ed25519(ref pk) => pk.as_bytes(),
        }
    }

    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), SignatureError> {
        match (self, signature) {
            (&SigningPublicKey::DsaSha1, &Signature::DsaSha1) => unimplemented!(),
            (&SigningPublicKey::EcdsaSha256P256, &Signature::EcdsaSha256P256) => unimplemented!(),
            (&SigningPublicKey::EcdsaSha384P384, &Signature::EcdsaSha384P384) => unimplemented!(),
            (&SigningPublicKey::EcdsaSha512P521, &Signature::EcdsaSha512P521) => unimplemented!(),
            (&SigningPublicKey::Ed25519(ref pk), &Signature::Ed25519(ref s)) => {
                pk.verify::<Sha512>(message, s).map_err(|e| e.into())
            }
            _ => {
                println!("Signature type doesn't match key type");
                Err(SignatureError::TypeMismatch)
            }
        }
    }
}

/// The private component of a signature keypair.
pub enum SigningPrivateKey {
    DsaSha1,
    EcdsaSha256P256,
    EcdsaSha384P384,
    EcdsaSha512P521,
    Ed25519(EdKeypair),
}

impl SigningPrivateKey {
    pub fn new() -> Self {
        SigningPrivateKey::with_type(&SigType::Ed25519)
    }

    pub fn with_type(sig_type: &SigType) -> Self {
        let mut rng = rand::thread_rng();
        match sig_type {
            &SigType::DsaSha1 => unimplemented!(),
            &SigType::EcdsaSha256P256 => unimplemented!(),
            &SigType::EcdsaSha384P384 => unimplemented!(),
            &SigType::EcdsaSha512P521 => unimplemented!(),
            &SigType::Ed25519 => loop {
                let mut keydata = [0u8; ED_SECRET_KEY_LENGTH];
                rng.fill(&mut keydata);
                match SigningPrivateKey::from_bytes(sig_type, &keydata) {
                    Ok(spk) => return spk,
                    Err(_) => continue,
                }
            },
        }
    }

    pub fn from_bytes(sig_type: &SigType, data: &[u8]) -> Result<Self, SignatureError> {
        match sig_type {
            &SigType::DsaSha1 => unimplemented!(),
            &SigType::EcdsaSha256P256 => unimplemented!(),
            &SigType::EcdsaSha384P384 => unimplemented!(),
            &SigType::EcdsaSha512P521 => unimplemented!(),
            &SigType::Ed25519 => {
                let secret = EdSecretKey::from_bytes(data)?;
                let public = EdPublicKey::from_secret::<Sha512>(&secret);
                Ok(SigningPrivateKey::Ed25519(EdKeypair { public, secret }))
            }
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            &SigningPrivateKey::DsaSha1 => unimplemented!(),
            &SigningPrivateKey::EcdsaSha256P256 => unimplemented!(),
            &SigningPrivateKey::EcdsaSha384P384 => unimplemented!(),
            &SigningPrivateKey::EcdsaSha512P521 => unimplemented!(),
            &SigningPrivateKey::Ed25519(ref kp) => kp.secret.as_bytes(),
        }
    }

    pub fn sign(&self, msg: &Vec<u8>) -> Signature {
        match self {
            &SigningPrivateKey::DsaSha1 => unimplemented!(),
            &SigningPrivateKey::EcdsaSha256P256 => unimplemented!(),
            &SigningPrivateKey::EcdsaSha384P384 => unimplemented!(),
            &SigningPrivateKey::EcdsaSha512P521 => unimplemented!(),
            &SigningPrivateKey::Ed25519(ref kp) => Signature::Ed25519(kp.sign::<Sha512>(msg)),
        }
    }
}

// TODO impl a way to reference a single key from multiple spots
impl Clone for SigningPrivateKey {
    fn clone(&self) -> Self {
        match self {
            &SigningPrivateKey::DsaSha1 => unimplemented!(),
            &SigningPrivateKey::EcdsaSha256P256 => unimplemented!(),
            &SigningPrivateKey::EcdsaSha384P384 => unimplemented!(),
            &SigningPrivateKey::EcdsaSha512P521 => unimplemented!(),
            &SigningPrivateKey::Ed25519(ref kp) => SigningPrivateKey::Ed25519(EdKeypair {
                public: kp.public.clone(),
                secret: EdSecretKey::from_bytes(kp.secret.as_bytes()).unwrap(),
            }),
        }
    }
}

/// A signature over some data.
#[derive(Clone, Debug, PartialEq)]
pub enum Signature {
    DsaSha1,
    EcdsaSha256P256,
    EcdsaSha384P384,
    EcdsaSha512P521,
    Ed25519(EdSignature),
}

impl Signature {
    pub fn from_bytes(sig_type: &SigType, data: &[u8]) -> Result<Self, SignatureError> {
        match sig_type {
            &SigType::DsaSha1 => unimplemented!(),
            &SigType::EcdsaSha256P256 => unimplemented!(),
            &SigType::EcdsaSha384P384 => unimplemented!(),
            &SigType::EcdsaSha512P521 => unimplemented!(),
            &SigType::Ed25519 => Ok(Signature::Ed25519(EdSignature::from_bytes(data)?)),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            &Signature::DsaSha1 => unimplemented!(),
            &Signature::EcdsaSha256P256 => unimplemented!(),
            &Signature::EcdsaSha384P384 => unimplemented!(),
            &Signature::EcdsaSha512P521 => unimplemented!(),
            &Signature::Ed25519(ref s) => Vec::from(&s.to_bytes()[..]),
        }
    }
}

/// A symmetric key used for AES-256 encryption.
pub struct SessionKey(pub [u8; 32]);

impl SessionKey {
    fn from_bytes(buf: &[u8; 32]) -> Self {
        let mut x = [0u8; 32];
        x.copy_from_slice(buf);
        SessionKey(x)
    }
}

//
// Algorithm implementations
//

// TODO: Use aesni if available
pub(crate) struct Aes256 {
    ti: Aes,
    buf: [u8; AES_BLOCK_SIZE],
    iv_enc: [u8; AES_BLOCK_SIZE],
    iv_dec: [u8; AES_BLOCK_SIZE],
}

impl Aes256 {
    pub fn new(
        key: &SessionKey,
        iv_enc: &[u8; AES_BLOCK_SIZE],
        iv_dec: &[u8; AES_BLOCK_SIZE],
    ) -> Self {
        let mut iv_enc_copy = [0; AES_BLOCK_SIZE];
        let mut iv_dec_copy = [0; AES_BLOCK_SIZE];
        iv_enc_copy.copy_from_slice(iv_enc);
        iv_dec_copy.copy_from_slice(iv_dec);
        Aes256 {
            ti: Aes::with_key(&key.0).unwrap(),
            buf: [0; AES_BLOCK_SIZE],
            iv_enc: iv_enc_copy,
            iv_dec: iv_dec_copy,
        }
    }

    fn encrypt(&mut self, block: &mut [u8; AES_BLOCK_SIZE]) {
        self.ti.encrypt(&mut self.buf, block);
        block.copy_from_slice(&self.buf);
    }

    fn decrypt(&mut self, block: &mut [u8; AES_BLOCK_SIZE]) {
        self.ti.decrypt(&mut self.buf, block);
        block.copy_from_slice(&self.buf);
    }

    pub fn encrypt_blocks(&mut self, buf: &mut [u8]) -> Option<usize> {
        // Wait until we have at least a block to encrypt
        if buf.len() < AES_BLOCK_SIZE {
            return None;
        }

        // Integer division, leaves extra bytes unencrypted at the end
        let end = buf.len() / AES_BLOCK_SIZE;
        for i in 0..end {
            // CBC mode, chained across received messages
            for j in 0..AES_BLOCK_SIZE {
                if i == 0 {
                    buf[j] ^= self.iv_enc[j];
                } else {
                    buf[i * AES_BLOCK_SIZE + j] ^= buf[(i - 1) * AES_BLOCK_SIZE + j];
                }
            }
            self.encrypt(array_mut_ref![buf, i * AES_BLOCK_SIZE, AES_BLOCK_SIZE]);
        }
        // Copy ciphertext from the last block for use with next message
        self.iv_enc
            .copy_from_slice(&buf[(end - 1) * AES_BLOCK_SIZE..end * AES_BLOCK_SIZE]);

        Some(end * AES_BLOCK_SIZE)
    }

    pub fn decrypt_blocks(&mut self, buf: &mut [u8]) -> Option<usize> {
        // Wait until we have at least a block to decrypt
        if buf.len() < AES_BLOCK_SIZE {
            return None;
        }

        // Integer division, leaves extra bytes undecrypted at the end
        let mut tmp_block = [0; AES_BLOCK_SIZE];
        let end = buf.len() / AES_BLOCK_SIZE;
        for i in 0..end {
            // Copy the block ciphertext for use in next round
            tmp_block.copy_from_slice(&buf[i * AES_BLOCK_SIZE..(i + 1) * AES_BLOCK_SIZE]);
            // Decrypt the block
            self.decrypt(array_mut_ref![buf, i * AES_BLOCK_SIZE, AES_BLOCK_SIZE]);
            // CBC mode, chained across received messages
            for j in 0..AES_BLOCK_SIZE {
                buf[i * AES_BLOCK_SIZE + j] ^= self.iv_dec[j];
            }
            // Swap for efficiency
            let tmp = self.iv_dec;
            self.iv_dec = tmp_block;
            tmp_block = tmp;
        }

        Some(end * AES_BLOCK_SIZE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sig_type_pad_len() {
        assert_eq!(SigType::DsaSha1.pad_len(&EncType::ElGamal2048), 0);
        assert_eq!(SigType::EcdsaSha256P256.pad_len(&EncType::ElGamal2048), 64);
        assert_eq!(SigType::EcdsaSha384P384.pad_len(&EncType::ElGamal2048), 32);
        assert_eq!(SigType::EcdsaSha512P521.pad_len(&EncType::ElGamal2048), 0);
        assert_eq!(SigType::Ed25519.pad_len(&EncType::ElGamal2048), 96);
    }

    #[test]
    fn test_sig_type_extra_data_len() {
        assert_eq!(SigType::DsaSha1.extra_data_len(&EncType::ElGamal2048), 0);
        assert_eq!(
            SigType::EcdsaSha256P256.extra_data_len(&EncType::ElGamal2048),
            0
        );
        assert_eq!(
            SigType::EcdsaSha384P384.extra_data_len(&EncType::ElGamal2048),
            0
        );
        assert_eq!(
            SigType::EcdsaSha512P521.extra_data_len(&EncType::ElGamal2048),
            4
        );
        assert_eq!(SigType::Ed25519.extra_data_len(&EncType::ElGamal2048), 0);
    }

    #[test]
    fn aes_256_ecb_test_vectors() {
        struct TestVector {
            key: SessionKey,
            plaintext: [u8; 16],
            ciphertext: [u8; 16],
        };
        // From https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/KAT_AES.zip
        // Source: http://csrc.nist.gov/groups/STM/cavp/block-ciphers.html
        let test_vectors = vec![
            TestVector {
                // ECBVarKey256 count 0
                key: SessionKey([
                    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ]),
                plaintext: [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00,
                ],
                ciphertext: [
                    0xe3, 0x5a, 0x6d, 0xcb, 0x19, 0xb2, 0x01, 0xa0, 0x1e, 0xbc, 0xfa, 0x8a, 0xa2,
                    0x2b, 0x57, 0x59,
                ],
            },
            TestVector {
                // ECBVarKey256 count 45
                key: SessionKey([
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ]),
                plaintext: [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00,
                ],
                ciphertext: [
                    0x82, 0xbd, 0xa1, 0x18, 0xa3, 0xed, 0x7a, 0xf3, 0x14, 0xfa, 0x2c, 0xcc, 0x5c,
                    0x07, 0xb7, 0x61,
                ],
            },
            TestVector {
                // ECBVarKey256 count 255
                key: SessionKey([
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                ]),
                plaintext: [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00,
                ],
                ciphertext: [
                    0x4b, 0xf8, 0x5f, 0x1b, 0x5d, 0x54, 0xad, 0xbc, 0x30, 0x7b, 0x0a, 0x04, 0x83,
                    0x89, 0xad, 0xcb,
                ],
            },
            TestVector {
                // ECBVarTxt256 count 0
                key: SessionKey([
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ]),
                plaintext: [
                    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00,
                ],
                ciphertext: [
                    0xdd, 0xc6, 0xbf, 0x79, 0x0c, 0x15, 0x76, 0x0d, 0x8d, 0x9a, 0xeb, 0x6f, 0x9a,
                    0x75, 0xfd, 0x4e,
                ],
            },
            TestVector {
                // ECBVarTxt256 count 77
                key: SessionKey([
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ]),
                plaintext: [
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00,
                ],
                ciphertext: [
                    0xb9, 0x5b, 0xa0, 0x5b, 0x33, 0x2d, 0xa6, 0x1e, 0xf6, 0x3a, 0x2b, 0x31, 0xfc,
                    0xad, 0x98, 0x79,
                ],
            },
            TestVector {
                // ECBVarTxt256 count 127
                key: SessionKey([
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ]),
                plaintext: [
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff,
                ],
                ciphertext: [
                    0xac, 0xda, 0xce, 0x80, 0x78, 0xa3, 0x2b, 0x1a, 0x18, 0x2b, 0xfa, 0x49, 0x87,
                    0xca, 0x13, 0x47,
                ],
            },
        ];

        let unused = [0u8; 16];
        for tv in test_vectors.iter() {
            let mut aes = Aes256::new(&tv.key, &unused, &unused);
            let mut block = [0u8; 16];
            block.copy_from_slice(&tv.plaintext);
            aes.encrypt(&mut block);
            assert_eq!(block, tv.ciphertext);
            aes.decrypt(&mut block);
            assert_eq!(block, tv.plaintext);
        }
    }

    #[test]
    fn aes_256_cbc_test_vectors() {
        struct TestVector {
            key: SessionKey,
            iv: [u8; 16],
            plaintext: Vec<u8>,
            ciphertext: Vec<u8>,
        };
        // From https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/aesmmt.zip
        // Source: http://csrc.nist.gov/groups/STM/cavp/block-ciphers.html
        let test_vectors = vec![
            TestVector {
                // CBCMMT256 encrypt count 0
                key: SessionKey([
                    0x6e, 0xd7, 0x6d, 0x2d, 0x97, 0xc6, 0x9f, 0xd1, 0x33, 0x95, 0x89, 0x52, 0x39,
                    0x31, 0xf2, 0xa6, 0xcf, 0xf5, 0x54, 0xb1, 0x5f, 0x73, 0x8f, 0x21, 0xec, 0x72,
                    0xdd, 0x97, 0xa7, 0x33, 0x09, 0x07,
                ]),
                iv: [
                    0x85, 0x1e, 0x87, 0x64, 0x77, 0x6e, 0x67, 0x96, 0xaa, 0xb7, 0x22, 0xdb, 0xb6,
                    0x44, 0xac, 0xe8,
                ],
                plaintext: vec![
                    0x62, 0x82, 0xb8, 0xc0, 0x5c, 0x5c, 0x15, 0x30, 0xb9, 0x7d, 0x48, 0x16, 0xca,
                    0x43, 0x47, 0x62,
                ],
                ciphertext: vec![
                    0x6a, 0xcc, 0x04, 0x14, 0x2e, 0x10, 0x0a, 0x65, 0xf5, 0x1b, 0x97, 0xad, 0xf5,
                    0x17, 0x2c, 0x41,
                ],
            },
            TestVector {
                // CBCMMT256 encrypt count 5
                key: SessionKey([
                    0x73, 0xb8, 0xfa, 0xf0, 0x0b, 0x33, 0x02, 0xac, 0x99, 0x85, 0x5c, 0xf6, 0xf9,
                    0xe9, 0xe4, 0x85, 0x18, 0x69, 0x0a, 0x59, 0x06, 0xa4, 0x86, 0x9d, 0x4d, 0xcf,
                    0x48, 0xd2, 0x82, 0xfa, 0xae, 0x2a,
                ]),
                iv: [
                    0xb3, 0xcb, 0x97, 0xa8, 0x0a, 0x53, 0x99, 0x12, 0xb8, 0xc2, 0x1f, 0x45, 0x0d,
                    0x3b, 0x93, 0x95,
                ],
                plaintext: vec![
                    0x3a, 0xde, 0xa6, 0xe0, 0x6e, 0x42, 0xc4, 0xf0, 0x41, 0x02, 0x14, 0x91, 0xf2,
                    0x77, 0x5e, 0xf6, 0x37, 0x8c, 0xb0, 0x88, 0x24, 0x16, 0x5e, 0xdc, 0x4f, 0x64,
                    0x48, 0xe2, 0x32, 0x17, 0x5b, 0x60, 0xd0, 0x34, 0x5b, 0x9f, 0x9c, 0x78, 0xdf,
                    0x65, 0x96, 0xec, 0x9d, 0x22, 0xb7, 0xb9, 0xe7, 0x6e, 0x8f, 0x3c, 0x76, 0xb3,
                    0x2d, 0x5d, 0x67, 0x27, 0x3f, 0x1d, 0x83, 0xfe, 0x7a, 0x6f, 0xc3, 0xdd, 0x3c,
                    0x49, 0x13, 0x91, 0x70, 0xfa, 0x57, 0x01, 0xb3, 0xbe, 0xac, 0x61, 0xb4, 0x90,
                    0xf0, 0xa9, 0xe1, 0x3f, 0x84, 0x46, 0x40, 0xc4, 0x50, 0x0f, 0x9a, 0xd3, 0x08,
                    0x7a, 0xdf, 0xb0, 0xae, 0x10,
                ],
                ciphertext: vec![
                    0xac, 0x3d, 0x6d, 0xba, 0xfe, 0x2e, 0x0f, 0x74, 0x06, 0x32, 0xfd, 0x9e, 0x82,
                    0x0b, 0xf6, 0x04, 0x4c, 0xd5, 0xb1, 0x55, 0x1c, 0xbb, 0x9c, 0xc0, 0x3c, 0x0b,
                    0x25, 0xc3, 0x9c, 0xcb, 0x7f, 0x33, 0xb8, 0x3a, 0xac, 0xfc, 0xa4, 0x0a, 0x32,
                    0x65, 0xf2, 0xbb, 0xff, 0x87, 0x91, 0x53, 0x44, 0x8a, 0xca, 0xcb, 0x88, 0xfc,
                    0xfb, 0x3b, 0xb7, 0xb1, 0x0f, 0xe4, 0x63, 0xa6, 0x8c, 0x01, 0x09, 0xf0, 0x28,
                    0x38, 0x2e, 0x3e, 0x55, 0x7b, 0x1a, 0xdf, 0x02, 0xed, 0x64, 0x8a, 0xb6, 0xbb,
                    0x89, 0x5d, 0xf0, 0x20, 0x5d, 0x26, 0xeb, 0xbf, 0xa9, 0xa5, 0xfd, 0x8c, 0xeb,
                    0xd8, 0xe4, 0xbe, 0xe3, 0xdc,
                ],
            },
            TestVector {
                // CBCMMT256 encrypt count 9
                key: SessionKey([
                    0x48, 0xbe, 0x59, 0x7e, 0x63, 0x2c, 0x16, 0x77, 0x23, 0x24, 0xc8, 0xd3, 0xfa,
                    0x1d, 0x9c, 0x5a, 0x9e, 0xcd, 0x01, 0x0f, 0x14, 0xec, 0x5d, 0x11, 0x0d, 0x3b,
                    0xfe, 0xc3, 0x76, 0xc5, 0x53, 0x2b,
                ]),
                iv: [
                    0xd6, 0xd5, 0x81, 0xb8, 0xcf, 0x04, 0xeb, 0xd3, 0xb6, 0xea, 0xa1, 0xb5, 0x3f,
                    0x04, 0x7e, 0xe1,
                ],
                plaintext: vec![
                    0x0c, 0x63, 0xd4, 0x13, 0xd3, 0x86, 0x45, 0x70, 0xe7, 0x0b, 0xb6, 0x61, 0x8b,
                    0xf8, 0xa4, 0xb9, 0x58, 0x55, 0x86, 0x68, 0x8c, 0x32, 0xbb, 0xa0, 0xa5, 0xec,
                    0xc1, 0x36, 0x2f, 0xad, 0xa7, 0x4a, 0xda, 0x32, 0xc5, 0x2a, 0xcf, 0xd1, 0xaa,
                    0x74, 0x44, 0xba, 0x56, 0x7b, 0x4e, 0x7d, 0xaa, 0xec, 0xf7, 0xcc, 0x1c, 0xb2,
                    0x91, 0x82, 0xaf, 0x16, 0x4a, 0xe5, 0x23, 0x2b, 0x00, 0x28, 0x68, 0x69, 0x56,
                    0x35, 0x59, 0x98, 0x07, 0xa9, 0xa7, 0xf0, 0x7a, 0x1f, 0x13, 0x7e, 0x97, 0xb1,
                    0xe1, 0xc9, 0xda, 0xbc, 0x89, 0xb6, 0xa5, 0xe4, 0xaf, 0xa9, 0xdb, 0x58, 0x55,
                    0xed, 0xaa, 0x57, 0x50, 0x56, 0xa8, 0xf4, 0xf8, 0x24, 0x22, 0x16, 0x24, 0x2b,
                    0xb0, 0xc2, 0x56, 0x31, 0x0d, 0x9d, 0x32, 0x98, 0x26, 0xac, 0x35, 0x3d, 0x71,
                    0x5f, 0xa3, 0x9f, 0x80, 0xce, 0xc1, 0x44, 0xd6, 0x42, 0x45, 0x58, 0xf9, 0xf7,
                    0x0b, 0x98, 0xc9, 0x20, 0x09, 0x6e, 0x0f, 0x2c, 0x85, 0x5d, 0x59, 0x48, 0x85,
                    0xa0, 0x06, 0x25, 0x88, 0x0e, 0x9d, 0xfb, 0x73, 0x41, 0x63, 0xce, 0xce, 0xf7,
                    0x2c, 0xf0, 0x30, 0xb8,
                ],
                ciphertext: vec![
                    0xfc, 0x58, 0x73, 0xe5, 0x0d, 0xe8, 0xfa, 0xf4, 0xc6, 0xb8, 0x4b, 0xa7, 0x07,
                    0xb0, 0x85, 0x4e, 0x9d, 0xb9, 0xab, 0x2e, 0x9f, 0x7d, 0x70, 0x7f, 0xbb, 0xa3,
                    0x38, 0xc6, 0x84, 0x3a, 0x18, 0xfc, 0x6f, 0xac, 0xeb, 0xaf, 0x66, 0x3d, 0x26,
                    0x29, 0x6f, 0xb3, 0x29, 0xb4, 0xd2, 0x6f, 0x18, 0x49, 0x4c, 0x79, 0xe0, 0x9e,
                    0x77, 0x96, 0x47, 0xf9, 0xba, 0xfa, 0x87, 0x48, 0x96, 0x30, 0xd7, 0x9f, 0x43,
                    0x01, 0x61, 0x0c, 0x23, 0x00, 0xc1, 0x9d, 0xbf, 0x31, 0x48, 0xb7, 0xca, 0xc8,
                    0xc4, 0xf4, 0x94, 0x41, 0x02, 0x75, 0x4f, 0x33, 0x2e, 0x92, 0xb6, 0xf7, 0xc5,
                    0xe7, 0x5b, 0xc6, 0x17, 0x9e, 0xb8, 0x77, 0xa0, 0x78, 0xd4, 0x71, 0x90, 0x09,
                    0x02, 0x17, 0x44, 0xc1, 0x4f, 0x13, 0xfd, 0x2a, 0x55, 0xa2, 0xb9, 0xc4, 0x4d,
                    0x18, 0x00, 0x06, 0x85, 0xa8, 0x45, 0xa4, 0xf6, 0x32, 0xc7, 0xc5, 0x6a, 0x77,
                    0x30, 0x6e, 0xfa, 0x66, 0xa2, 0x4d, 0x05, 0xd0, 0x88, 0xdc, 0xd7, 0xc1, 0x3f,
                    0xe2, 0x4f, 0xc4, 0x47, 0x27, 0x59, 0x65, 0xdb, 0x9e, 0x4d, 0x37, 0xfb, 0xc9,
                    0x30, 0x44, 0x48, 0xcd,
                ],
            },
            TestVector {
                // CBCMMT256 decrypt count 2
                key: SessionKey([
                    0x54, 0x68, 0x27, 0x28, 0xdb, 0x50, 0x35, 0xeb, 0x04, 0xb7, 0x96, 0x45, 0xc6,
                    0x4a, 0x95, 0x60, 0x6a, 0xbb, 0x6b, 0xa3, 0x92, 0xb6, 0x63, 0x3d, 0x79, 0x17,
                    0x3c, 0x02, 0x7c, 0x5a, 0xcf, 0x77,
                ]),
                iv: [
                    0x2e, 0xb9, 0x42, 0x97, 0x77, 0x28, 0x51, 0x96, 0x3d, 0xd3, 0x9a, 0x1e, 0xb9,
                    0x5d, 0x43, 0x8f,
                ],
                plaintext: vec![
                    0x0f, 0xaa, 0x5d, 0x01, 0xb9, 0xaf, 0xad, 0x3b, 0xb5, 0x19, 0x57, 0x5d, 0xaa,
                    0xf4, 0xc6, 0x0a, 0x5e, 0xd4, 0xca, 0x2b, 0xa2, 0x0c, 0x62, 0x5b, 0xc4, 0xf0,
                    0x87, 0x99, 0xad, 0xdc, 0xf8, 0x9d, 0x19, 0x79, 0x6d, 0x1e, 0xff, 0x0b, 0xd7,
                    0x90, 0xc6, 0x22, 0xdc, 0x22, 0xc1, 0x09, 0x4e, 0xc7,
                ],
                ciphertext: vec![
                    0xe4, 0x04, 0x6d, 0x05, 0x38, 0x5a, 0xb7, 0x89, 0xc6, 0xa7, 0x28, 0x66, 0xe0,
                    0x83, 0x50, 0xf9, 0x3f, 0x58, 0x3e, 0x2a, 0x00, 0x5c, 0xa0, 0xfa, 0xec, 0xc3,
                    0x2b, 0x5c, 0xfc, 0x32, 0x3d, 0x46, 0x1c, 0x76, 0xc1, 0x07, 0x30, 0x76, 0x54,
                    0xdb, 0x55, 0x66, 0xa5, 0xbd, 0x69, 0x3e, 0x22, 0x7c,
                ],
            },
            TestVector {
                // CBCMMT256 decrypt count 4
                key: SessionKey([
                    0x3a, 0xe3, 0x8d, 0x4e, 0xbf, 0x7e, 0x7f, 0x6d, 0xc0, 0xa1, 0xe3, 0x1e, 0x5e,
                    0xfa, 0x7c, 0xa1, 0x23, 0xfd, 0xc3, 0x21, 0xe5, 0x33, 0xe7, 0x9f, 0xed, 0xd5,
                    0x13, 0x2c, 0x59, 0x99, 0xef, 0x5b,
                ]),
                iv: [
                    0x36, 0xd5, 0x5d, 0xc9, 0xed, 0xf8, 0x66, 0x9b, 0xee, 0xcd, 0x9a, 0x2a, 0x02,
                    0x90, 0x92, 0xb9,
                ],
                plaintext: vec![
                    0x8d, 0x22, 0xdb, 0x30, 0xc4, 0x25, 0x3c, 0x3e, 0x3a, 0xdd, 0x96, 0x85, 0xc1,
                    0x4d, 0x55, 0xb0, 0x5f, 0x7c, 0xf7, 0x62, 0x6c, 0x52, 0xcc, 0xcf, 0xcb, 0xe9,
                    0xb9, 0x9f, 0xd8, 0x91, 0x36, 0x63, 0xb8, 0xb1, 0xf2, 0x2e, 0x27, 0x7a, 0x4c,
                    0xc3, 0xd0, 0xe7, 0xe9, 0x78, 0xa3, 0x47, 0x82, 0xeb, 0x87, 0x68, 0x67, 0x55,
                    0x6a, 0xd4, 0x72, 0x84, 0x86, 0xd5, 0xe8, 0x90, 0xea, 0x73, 0x82, 0x43, 0xe3,
                    0x70, 0x0a, 0x69, 0x6d, 0x6e, 0xb5, 0x8c, 0xd8, 0x1c, 0x0e, 0x60, 0xeb, 0x12,
                    0x1c, 0x50,
                ],
                ciphertext: vec![
                    0xd5, 0x0e, 0xa4, 0x8c, 0x89, 0x62, 0x96, 0x2f, 0x7c, 0x3d, 0x30, 0x1f, 0xa9,
                    0xf8, 0x77, 0x24, 0x50, 0x26, 0xc2, 0x04, 0xa7, 0x77, 0x12, 0x92, 0xcd, 0xdc,
                    0xa1, 0xe7, 0xff, 0xeb, 0xbe, 0xf0, 0x0e, 0x86, 0xd7, 0x29, 0x10, 0xb7, 0xd8,
                    0xa7, 0x56, 0xdf, 0xb4, 0x5c, 0x9f, 0x10, 0x40, 0x97, 0x8b, 0xb7, 0x48, 0xca,
                    0x53, 0x7e, 0xdd, 0x90, 0xb6, 0x70, 0xec, 0xee, 0x37, 0x5e, 0x15, 0xd9, 0x85,
                    0x82, 0xb9, 0xf9, 0x3b, 0x63, 0x55, 0xad, 0xc9, 0xf8, 0x0f, 0x4f, 0xb2, 0x10,
                    0x8f, 0xb9,
                ],
            },
            TestVector {
                // CBCMMT256 decrypt count 7
                key: SessionKey([
                    0x31, 0x35, 0x8e, 0x8a, 0xf3, 0x4d, 0x6a, 0xc3, 0x1c, 0x95, 0x8b, 0xbd, 0x5c,
                    0x8f, 0xb3, 0x3c, 0x33, 0x47, 0x14, 0xbf, 0xfb, 0x41, 0x70, 0x0d, 0x28, 0xb0,
                    0x7f, 0x11, 0xcf, 0xe8, 0x91, 0xe7,
                ]),
                iv: [
                    0x14, 0x45, 0x16, 0x24, 0x6a, 0x75, 0x2c, 0x32, 0x90, 0x56, 0xd8, 0x84, 0xda,
                    0xf3, 0xc8, 0x9d,
                ],
                plaintext: vec![
                    0xcf, 0xc1, 0x55, 0xa3, 0x96, 0x7d, 0xe3, 0x47, 0xf5, 0x8f, 0xa2, 0xe8, 0xbb,
                    0xeb, 0x41, 0x83, 0xd6, 0xd3, 0x2f, 0x74, 0x27, 0x15, 0x5e, 0x6a, 0xb3, 0x9c,
                    0xdd, 0xf2, 0xe6, 0x27, 0xc5, 0x72, 0xac, 0xae, 0x02, 0xf1, 0xf2, 0x43, 0xf3,
                    0xb7, 0x84, 0xe7, 0x3e, 0x21, 0xe7, 0xe5, 0x20, 0xea, 0xcd, 0x3b, 0xef, 0xaf,
                    0xbe, 0xe8, 0x14, 0x86, 0x73, 0x34, 0xc6, 0xee, 0x8c, 0x2f, 0x0e, 0xe7, 0x37,
                    0x6d, 0x3c, 0x72, 0x72, 0x8c, 0xde, 0x78, 0x13, 0x17, 0x3d, 0xbd, 0xfe, 0x33,
                    0x57, 0xde, 0xac, 0x41, 0xd3, 0xae, 0x2a, 0x04, 0x22, 0x9c, 0x02, 0x62, 0xf2,
                    0xd1, 0x09, 0xd0, 0x1f, 0x5d, 0x03, 0xe7, 0xf8, 0x48, 0xfb, 0x50, 0xc2, 0x88,
                    0x49, 0x14, 0x6c, 0x02, 0xa2, 0xf4, 0xeb, 0xf7, 0xd7, 0xff, 0xe3, 0xc9, 0xd4,
                    0x0e, 0x31, 0x97, 0x0b, 0xf1, 0x51, 0x87, 0x36, 0x72, 0xef, 0x2b,
                ],
                ciphertext: vec![
                    0xb3, 0x2e, 0x2b, 0x17, 0x1b, 0x63, 0x82, 0x70, 0x34, 0xeb, 0xb0, 0xd1, 0x90,
                    0x9f, 0x7e, 0xf1, 0xd5, 0x1c, 0x5f, 0x82, 0xc1, 0xbb, 0x9b, 0xc2, 0x6b, 0xc4,
                    0xac, 0x4d, 0xcc, 0xde, 0xe8, 0x35, 0x7d, 0xca, 0x61, 0x54, 0xc2, 0x51, 0x0a,
                    0xe1, 0xc8, 0x7b, 0x1b, 0x42, 0x2b, 0x02, 0xb6, 0x21, 0xbb, 0x06, 0xca, 0xc2,
                    0x80, 0x02, 0x38, 0x94, 0xfc, 0xff, 0x34, 0x06, 0xaf, 0x08, 0xee, 0x9b, 0xe1,
                    0xdd, 0x72, 0x41, 0x9b, 0xec, 0xcd, 0xdf, 0xf7, 0x7c, 0x72, 0x2d, 0x99, 0x2c,
                    0xdc, 0xc8, 0x7e, 0x9c, 0x74, 0x86, 0xf5, 0x6a, 0xb4, 0x06, 0xea, 0x60, 0x8d,
                    0x8c, 0x6a, 0xeb, 0x06, 0x0c, 0x64, 0xcf, 0x27, 0x85, 0xad, 0x1a, 0x15, 0x91,
                    0x47, 0x56, 0x7e, 0x39, 0xe3, 0x03, 0x37, 0x0d, 0xa4, 0x45, 0x24, 0x75, 0x26,
                    0xd9, 0x59, 0x42, 0xbf, 0x4d, 0x7e, 0x88, 0x05, 0x71, 0x78, 0xb0,
                ],
            },
        ];

        for tv in test_vectors.iter() {
            let mut aes = Aes256::new(&tv.key, &tv.iv, &tv.iv);
            let mut blocks = tv.plaintext.clone();
            aes.encrypt_blocks(&mut blocks);
            assert_eq!(blocks, tv.ciphertext);
            aes.decrypt_blocks(&mut blocks);
            assert_eq!(blocks, tv.plaintext);
        }
    }
}
