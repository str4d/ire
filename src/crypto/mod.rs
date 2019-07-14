//! Cryptographic types and operations.

use aes::{self, block_cipher_trait::generic_array::GenericArray as AesGenericArray};
use block_modes::{block_padding::ZeroPadding, BlockMode, BlockModeIv, Cbc};
use i2p_ring::signature as ring_signature;
use nom::Err;
use rand::Rng;
use signatory::{
    ecdsa::{
        curve::{NistP256, NistP384, WeierstrassCurve},
        FixedSignature,
    },
    ed25519,
    generic_array::{typenum::Unsigned, GenericArray as SignatoryGenericArray},
    public_key, sign, verify, verify_sha256, verify_sha384, EcdsaPublicKey, Ed25519PublicKey,
    Ed25519Seed, Ed25519Signature, Signature as SignatorySignature,
};
use signatory_dalek::{Ed25519Signer, Ed25519Verifier};
use signatory_ring::ecdsa::{P256Verifier, P384Verifier};
use std::fmt;
use untrusted;

use crate::constants;
use crate::util::fmt_colon_delimited_hex;

#[allow(needless_pass_by_value)]
pub(crate) mod frame;

pub(crate) mod dh;
mod dsa;
pub mod elgamal;
pub(crate) mod math;

pub(crate) const AES_BLOCK_SIZE: usize = 16;

/// Cryptographic errors
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidCiphertext,
    InvalidKey,
    InvalidMessage,
    InvalidSignature,
    KeyExpired,
    NoSignature,
    SigningFailed,
    TypeMismatch,
}

#[cfg_attr(tarpaulin, skip)]
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidCiphertext => "Invalid ciphertext".fmt(f),
            Error::InvalidKey => "Invalid cryptographic key".fmt(f),
            Error::InvalidMessage => "Invalid message".fmt(f),
            Error::InvalidSignature => "Bad signature".fmt(f),
            Error::KeyExpired => "Key expired".fmt(f),
            Error::NoSignature => "No signature".fmt(f),
            Error::SigningFailed => "Failed to create a signature".fmt(f),
            Error::TypeMismatch => "Signature type doesn't match key type".fmt(f),
        }
    }
}

/// Various signature algorithms present on the network.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SigType {
    DsaSha1,
    EcdsaSha256P256,
    EcdsaSha384P384,
    EcdsaSha512P521,
    Rsa2048Sha256,
    Rsa3072Sha384,
    Rsa4096Sha512,
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

    pub fn code(self) -> u16 {
        match self {
            SigType::DsaSha1 => constants::DSA_SHA1,
            SigType::EcdsaSha256P256 => constants::ECDSA_SHA256_P256,
            SigType::EcdsaSha384P384 => constants::ECDSA_SHA384_P384,
            SigType::EcdsaSha512P521 => constants::ECDSA_SHA512_P521,
            SigType::Rsa2048Sha256 => constants::RSA_SHA256_2048,
            SigType::Rsa3072Sha384 => constants::RSA_SHA384_3072,
            SigType::Rsa4096Sha512 => constants::RSA_SHA512_4096,
            SigType::Ed25519 => constants::ED25519,
        }
    }

    pub fn pubkey_len(self) -> u32 {
        match self {
            SigType::DsaSha1 => 128,
            SigType::EcdsaSha256P256 => <NistP256 as WeierstrassCurve>::UntaggedPointSize::to_u32(),
            SigType::EcdsaSha384P384 => <NistP384 as WeierstrassCurve>::UntaggedPointSize::to_u32(),
            SigType::EcdsaSha512P521 => 132,
            SigType::Rsa2048Sha256 => 256,
            SigType::Rsa3072Sha384 => 384,
            SigType::Rsa4096Sha512 => 512,
            SigType::Ed25519 => ed25519::PUBLIC_KEY_SIZE as u32,
        }
    }

    pub fn privkey_len(self) -> u32 {
        match self {
            SigType::DsaSha1 => 20,
            SigType::EcdsaSha256P256 => <NistP256 as WeierstrassCurve>::ScalarSize::to_u32(),
            SigType::EcdsaSha384P384 => <NistP384 as WeierstrassCurve>::ScalarSize::to_u32(),
            SigType::EcdsaSha512P521 => 66,
            SigType::Rsa2048Sha256 => 512,
            SigType::Rsa3072Sha384 => 768,
            SigType::Rsa4096Sha512 => 1024,
            SigType::Ed25519 => ed25519::SEED_SIZE as u32,
        }
    }

    pub fn sig_len(self) -> u32 {
        match self {
            SigType::DsaSha1 => 40,
            SigType::EcdsaSha256P256 => {
                <NistP256 as WeierstrassCurve>::FixedSignatureSize::to_u32()
            }
            SigType::EcdsaSha384P384 => {
                <NistP384 as WeierstrassCurve>::FixedSignatureSize::to_u32()
            }
            SigType::EcdsaSha512P521 => 132,
            SigType::Rsa2048Sha256 => 256,
            SigType::Rsa3072Sha384 => 384,
            SigType::Rsa4096Sha512 => 512,
            SigType::Ed25519 => ed25519::SIGNATURE_SIZE as u32,
        }
    }

    // Returns a number between 0 and 128
    pub fn pad_len(self, enc_type: EncType) -> usize {
        match enc_type {
            EncType::ElGamal2048 => {
                constants::KEYCERT_SIGKEY_BYTES.saturating_sub(self.pubkey_len() as usize)
            }
        }
    }

    pub fn extra_data_len(self, enc_type: EncType) -> usize {
        match enc_type {
            EncType::ElGamal2048 => {
                (self.pubkey_len() as usize).saturating_sub(constants::KEYCERT_SIGKEY_BYTES)
            }
        }
    }
}

/// Field in a RouterInfo or Destination KeyCertificate.
#[derive(Clone, Copy, Debug, PartialEq)]
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

    pub fn code(self) -> u16 {
        match self {
            EncType::ElGamal2048 => constants::ELGAMAL2048,
        }
    }

    pub fn extra_data_len(self, _sig_type: SigType) -> usize {
        match self {
            EncType::ElGamal2048 => 0,
        }
    }
}

//
// Key material and signatures
//

/// Key material for initiating various end-to-end encryption algorithms.
#[derive(Clone, Debug)]
pub enum CryptoKey {
    ElGamalAES(PublicKey),
    Unsupported(u16, Vec<u8>),
}

pub enum CryptoSecretKey {
    ElGamalAES(PrivateKey),
}

impl CryptoSecretKey {
    pub fn new_keypair() -> (Self, CryptoKey) {
        let (privkey, pubkey) = elgamal::KeyPairGenerator::generate();
        (
            CryptoSecretKey::ElGamalAES(privkey),
            CryptoKey::ElGamalAES(pubkey),
        )
    }
}

/// The public component of an ElGamal encryption keypair. Represents only the
/// exponent, not the primes (which are constants).
pub struct PublicKey(pub [u8; 256]);

impl PublicKey {
    fn from_bytes(buf: &[u8; 256]) -> Self {
        let mut x = [0u8; 256];
        x.copy_from_slice(buf);
        PublicKey(x)
    }
}

impl Clone for PublicKey {
    fn clone(&self) -> Self {
        PublicKey::from_bytes(&self.0)
    }
}

#[cfg_attr(tarpaulin, skip)]
impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "PublicKey(")?;
        fmt_colon_delimited_hex(f, &self.0[..])?;
        write!(f, ")")
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
    pub fn new_keypair() -> (Self, PublicKey) {
        elgamal::KeyPairGenerator::generate()
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

#[cfg_attr(tarpaulin, skip)]
impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "PrivateKey(")?;
        fmt_colon_delimited_hex(f, &self.0[..])?;
        write!(f, ")")
    }
}

/// The public component of a signature keypair.
#[derive(Clone, Debug, PartialEq)]
pub enum SigningPublicKey {
    DsaSha1(dsa::DsaPublicKey),
    EcdsaSha256P256(EcdsaPublicKey<NistP256>),
    EcdsaSha384P384(EcdsaPublicKey<NistP384>),
    EcdsaSha512P521,
    Ed25519(Ed25519PublicKey),
}

impl SigningPublicKey {
    pub fn sig_type(&self) -> SigType {
        match *self {
            SigningPublicKey::DsaSha1(_) => SigType::DsaSha1,
            SigningPublicKey::EcdsaSha256P256(_) => SigType::EcdsaSha256P256,
            SigningPublicKey::EcdsaSha384P384(_) => SigType::EcdsaSha384P384,
            SigningPublicKey::EcdsaSha512P521 => SigType::EcdsaSha512P521,
            SigningPublicKey::Ed25519(_) => SigType::Ed25519,
        }
    }
}

impl SigningPublicKey {
    pub fn from_bytes(sig_type: SigType, data: &[u8]) -> Result<Self, Error> {
        match sig_type {
            SigType::DsaSha1 => Ok(SigningPublicKey::DsaSha1(dsa::DsaPublicKey::from_bytes(
                data,
            )?)),
            SigType::EcdsaSha256P256 => Ok(SigningPublicKey::EcdsaSha256P256(
                EcdsaPublicKey::from_untagged_point(SignatoryGenericArray::from_slice(data)),
            )),
            SigType::EcdsaSha384P384 => Ok(SigningPublicKey::EcdsaSha384P384(
                EcdsaPublicKey::from_untagged_point(SignatoryGenericArray::from_slice(data)),
            )),
            SigType::EcdsaSha512P521 => unimplemented!(),
            SigType::Rsa2048Sha256 | SigType::Rsa3072Sha384 | SigType::Rsa4096Sha512 => {
                panic!("Online verifying not supported")
            }
            SigType::Ed25519 => Ok(SigningPublicKey::Ed25519(
                Ed25519PublicKey::from_bytes(data).map_err(|_| Error::InvalidKey)?,
            )),
        }
    }

    pub fn from_secret(priv_key: &SigningPrivateKey) -> Result<Self, Error> {
        match *priv_key {
            SigningPrivateKey::DsaSha1 => unimplemented!(),
            SigningPrivateKey::EcdsaSha256P256 => unimplemented!(),
            SigningPrivateKey::EcdsaSha384P384 => unimplemented!(),
            SigningPrivateKey::EcdsaSha512P521 => unimplemented!(),
            SigningPrivateKey::Ed25519(ref seed) => Ok(SigningPublicKey::Ed25519(
                public_key(&Ed25519Signer::from(seed)).map_err(|_| Error::InvalidKey)?,
            )),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match *self {
            SigningPublicKey::DsaSha1(ref pk) => pk.as_bytes(),
            SigningPublicKey::EcdsaSha256P256(ref pk) => &pk.as_bytes()[1..],
            SigningPublicKey::EcdsaSha384P384(ref pk) => &pk.as_bytes()[1..],
            SigningPublicKey::EcdsaSha512P521 => unimplemented!(),
            SigningPublicKey::Ed25519(ref pk) => pk.as_bytes(),
        }
    }

    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), Error> {
        match (self, signature) {
            (&SigningPublicKey::DsaSha1(ref pk), &Signature::DsaSha1(ref s)) => {
                if pk.verify(message, s) {
                    Ok(())
                } else {
                    Err(Error::InvalidSignature)
                }
            }
            (&SigningPublicKey::EcdsaSha256P256(ref pk), &Signature::EcdsaSha256P256(ref s)) => {
                verify_sha256(&P256Verifier::from(pk), message, s)
                    .map_err(|_| Error::InvalidSignature)
            }
            (&SigningPublicKey::EcdsaSha384P384(ref pk), &Signature::EcdsaSha384P384(ref s)) => {
                verify_sha384(&P384Verifier::from(pk), message, s)
                    .map_err(|_| Error::InvalidSignature)
            }
            (&SigningPublicKey::EcdsaSha512P521, &Signature::EcdsaSha512P521) => unimplemented!(),
            (&SigningPublicKey::Ed25519(ref pk), &Signature::Ed25519(ref s)) => {
                verify(&Ed25519Verifier::from(pk), message, s).map_err(|_| Error::InvalidSignature)
            }
            _ => Err(Error::TypeMismatch),
        }
    }
}

/// The private component of a signature keypair.
pub enum SigningPrivateKey {
    DsaSha1,
    EcdsaSha256P256,
    EcdsaSha384P384,
    EcdsaSha512P521,
    Ed25519(Ed25519Seed),
}

impl SigningPrivateKey {
    pub fn new() -> Self {
        SigningPrivateKey::with_type(SigType::Ed25519)
    }

    pub fn with_type(sig_type: SigType) -> Self {
        match sig_type {
            SigType::DsaSha1 => unimplemented!(),
            SigType::EcdsaSha256P256 => unimplemented!(),
            SigType::EcdsaSha384P384 => unimplemented!(),
            SigType::EcdsaSha512P521 => unimplemented!(),
            SigType::Rsa2048Sha256 | SigType::Rsa3072Sha384 | SigType::Rsa4096Sha512 => {
                panic!("Online signing not supported")
            }
            SigType::Ed25519 => SigningPrivateKey::Ed25519(Ed25519Seed::generate()),
        }
    }

    pub fn from_bytes(sig_type: SigType, data: &[u8]) -> Result<Self, Error> {
        match sig_type {
            SigType::DsaSha1 => unimplemented!(),
            SigType::EcdsaSha256P256 => unimplemented!(),
            SigType::EcdsaSha384P384 => unimplemented!(),
            SigType::EcdsaSha512P521 => unimplemented!(),
            SigType::Rsa2048Sha256 | SigType::Rsa3072Sha384 | SigType::Rsa4096Sha512 => {
                panic!("Online signing not supported")
            }
            SigType::Ed25519 => Ok(SigningPrivateKey::Ed25519(
                Ed25519Seed::from_bytes(data).map_err(|_| Error::InvalidKey)?,
            )),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match *self {
            SigningPrivateKey::DsaSha1 => unimplemented!(),
            SigningPrivateKey::EcdsaSha256P256 => unimplemented!(),
            SigningPrivateKey::EcdsaSha384P384 => unimplemented!(),
            SigningPrivateKey::EcdsaSha512P521 => unimplemented!(),
            SigningPrivateKey::Ed25519(ref seed) => seed.as_secret_slice(),
        }
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Signature, Error> {
        match *self {
            SigningPrivateKey::DsaSha1 => unimplemented!(),
            SigningPrivateKey::EcdsaSha256P256 => unimplemented!(),
            SigningPrivateKey::EcdsaSha384P384 => unimplemented!(),
            SigningPrivateKey::EcdsaSha512P521 => unimplemented!(),
            SigningPrivateKey::Ed25519(ref seed) => Ok(Signature::Ed25519(
                sign(&Ed25519Signer::from(seed), msg).map_err(|_| Error::SigningFailed)?,
            )),
        }
    }
}

// TODO impl a way to reference a single key from multiple spots
impl Clone for SigningPrivateKey {
    fn clone(&self) -> Self {
        match *self {
            SigningPrivateKey::DsaSha1 => unimplemented!(),
            SigningPrivateKey::EcdsaSha256P256 => unimplemented!(),
            SigningPrivateKey::EcdsaSha384P384 => unimplemented!(),
            SigningPrivateKey::EcdsaSha512P521 => unimplemented!(),
            SigningPrivateKey::Ed25519(ref seed) => {
                SigningPrivateKey::Ed25519(Ed25519Seed::from_bytes(seed.as_secret_slice()).unwrap())
            }
        }
    }
}

/// The public component of an offline signature keypair.
#[derive(Clone, PartialEq)]
pub enum OfflineSigningPublicKey {
    Rsa2048Sha256(Vec<u8>),
    Rsa3072Sha384(Vec<u8>),
    Rsa4096Sha512(Vec<u8>),
}

#[cfg_attr(tarpaulin, skip)]
impl fmt::Debug for OfflineSigningPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "OfflineSigningPublicKey(")?;
        match self {
            OfflineSigningPublicKey::Rsa2048Sha256(key) => {
                write!(f, "Rsa2048Sha256(")?;
                fmt_colon_delimited_hex(f, key)?;
                write!(f, ")")?;
            }
            OfflineSigningPublicKey::Rsa3072Sha384(key) => {
                write!(f, "Rsa3072Sha384(")?;
                fmt_colon_delimited_hex(f, key)?;
                write!(f, ")")?;
            }
            OfflineSigningPublicKey::Rsa4096Sha512(key) => {
                write!(f, "Rsa4096Sha512(")?;
                fmt_colon_delimited_hex(f, key)?;
                write!(f, ")")?;
            }
        };
        write!(f, ")")
    }
}

impl OfflineSigningPublicKey {
    pub fn from_bytes(sig_type: SigType, data: &[u8]) -> Result<Self, Error> {
        match sig_type {
            SigType::Rsa2048Sha256 | SigType::Rsa3072Sha384 | SigType::Rsa4096Sha512 => {
                // Ring requires the binary RSAPublicKey format
                let mut pub_key_der = Vec::with_capacity(data.len());
                pub_key_der.extend_from_slice(data);
                Ok(match sig_type {
                    SigType::Rsa2048Sha256 => OfflineSigningPublicKey::Rsa2048Sha256(pub_key_der),
                    SigType::Rsa3072Sha384 => OfflineSigningPublicKey::Rsa3072Sha384(pub_key_der),
                    SigType::Rsa4096Sha512 => OfflineSigningPublicKey::Rsa4096Sha512(pub_key_der),
                    _ => unreachable!(),
                })
            }
            _ => panic!("Invalid offline SigType"),
        }
    }

    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), Error> {
        match (self, signature) {
            (&OfflineSigningPublicKey::Rsa2048Sha256(ref pk), &Signature::Rsa2048Sha256(ref s)) => {
                ring_signature::verify(
                    &ring_signature::RSA_PKCS1_2048_8192_SHA256_RAW,
                    untrusted::Input::from(pk),
                    untrusted::Input::from(message),
                    untrusted::Input::from(s),
                )
                .map_err(|_| Error::InvalidSignature)
            }
            (&OfflineSigningPublicKey::Rsa3072Sha384(ref pk), &Signature::Rsa3072Sha384(ref s)) => {
                ring_signature::verify(
                    &ring_signature::RSA_PKCS1_3072_8192_SHA384_RAW,
                    untrusted::Input::from(pk),
                    untrusted::Input::from(message),
                    untrusted::Input::from(s),
                )
                .map_err(|_| Error::InvalidSignature)
            }
            (&OfflineSigningPublicKey::Rsa4096Sha512(ref pk), &Signature::Rsa4096Sha512(ref s)) => {
                ring_signature::verify(
                    &ring_signature::RSA_PKCS1_4096_8192_SHA512_RAW,
                    untrusted::Input::from(pk),
                    untrusted::Input::from(message),
                    untrusted::Input::from(s),
                )
                .map_err(|_| Error::InvalidSignature)
            }
            _ => Err(Error::TypeMismatch),
        }
    }
}

/// A signature over some data.
#[derive(Clone, Debug, PartialEq)]
pub enum Signature {
    DsaSha1(dsa::DsaSignature),
    EcdsaSha256P256(FixedSignature<NistP256>),
    EcdsaSha384P384(FixedSignature<NistP384>),
    EcdsaSha512P521,
    Rsa2048Sha256(Vec<u8>),
    Rsa3072Sha384(Vec<u8>),
    Rsa4096Sha512(Vec<u8>),
    Ed25519(Ed25519Signature),
    Unsupported(Vec<u8>),
}

impl Signature {
    pub fn from_bytes(sig_type: SigType, data: &[u8]) -> Result<Self, Error> {
        match sig_type {
            SigType::DsaSha1 => Ok(Signature::DsaSha1(dsa::DsaSignature::from_bytes(data)?)),
            SigType::EcdsaSha256P256 => Ok(Signature::EcdsaSha256P256(
                FixedSignature::from_bytes(data).map_err(|_| Error::InvalidSignature)?,
            )),
            SigType::EcdsaSha384P384 => Ok(Signature::EcdsaSha384P384(
                FixedSignature::from_bytes(data).map_err(|_| Error::InvalidSignature)?,
            )),
            SigType::Ed25519 => Ok(Signature::Ed25519(
                Ed25519Signature::from_bytes(data).map_err(|_| Error::InvalidSignature)?,
            )),
            SigType::EcdsaSha512P521
            | SigType::Rsa2048Sha256
            | SigType::Rsa3072Sha384
            | SigType::Rsa4096Sha512 => {
                let mut sig = Vec::with_capacity(sig_type.sig_len() as usize);
                sig.extend_from_slice(&data[..sig_type.sig_len() as usize]);
                Ok(match sig_type {
                    SigType::Rsa2048Sha256 => Signature::Rsa2048Sha256(sig),
                    SigType::Rsa3072Sha384 => Signature::Rsa3072Sha384(sig),
                    SigType::Rsa4096Sha512 => Signature::Rsa4096Sha512(sig),
                    _ => Signature::Unsupported(sig),
                })
            }
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match *self {
            Signature::DsaSha1(ref s) => s.to_bytes(),
            Signature::EcdsaSha256P256(ref s) => Vec::from(s.as_ref()),
            Signature::EcdsaSha384P384(ref s) => Vec::from(s.as_ref()),
            Signature::EcdsaSha512P521 => unimplemented!(),
            Signature::Rsa2048Sha256(ref s) => s.clone(),
            Signature::Rsa3072Sha384(ref s) => s.clone(),
            Signature::Rsa4096Sha512(ref s) => s.clone(),
            Signature::Ed25519(ref s) => Vec::from(&s.as_bytes()[..]),
            Signature::Unsupported(ref s) => s.clone(),
        }
    }
}

/// A symmetric key used for AES-256 encryption.
#[derive(Clone, Debug, PartialEq)]
pub struct SessionKey(pub [u8; 32]);

impl SessionKey {
    pub fn generate<R: Rng>(rng: &mut R) -> Self {
        let mut x = [0; 32];
        rng.fill(&mut x);
        SessionKey(x)
    }

    fn from_bytes(buf: &[u8; 32]) -> Self {
        let mut x = [0u8; 32];
        x.copy_from_slice(buf);
        SessionKey(x)
    }
}

//
// Algorithm implementations
//

pub(crate) struct Aes256 {
    cbc_enc: Cbc<aes::Aes256, ZeroPadding>,
    cbc_dec: Cbc<aes::Aes256, ZeroPadding>,
}

impl Aes256 {
    pub fn new(key: &SessionKey, iv_enc: &[u8], iv_dec: &[u8]) -> Self {
        let key = AesGenericArray::from_slice(&key.0);
        Aes256 {
            cbc_enc: Cbc::new_fixkey(key, AesGenericArray::from_slice(iv_enc)),
            cbc_dec: Cbc::new_fixkey(key, AesGenericArray::from_slice(iv_dec)),
        }
    }

    pub fn encrypt_blocks(&mut self, buf: &mut [u8]) -> Option<usize> {
        // Wait until we have at least a block to encrypt
        if buf.len() < AES_BLOCK_SIZE {
            return None;
        }

        // Integer division, leaves extra bytes unencrypted at the end
        let end = (buf.len() / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
        match self.cbc_enc.encrypt_nopad(&mut buf[..end]) {
            Ok(_) => Some(end),
            Err(_) => None,
        }
    }

    pub fn decrypt_blocks(&mut self, buf: &mut [u8]) -> Option<usize> {
        // Wait until we have at least a block to decrypt
        if buf.len() < AES_BLOCK_SIZE {
            return None;
        }

        // Integer division, leaves extra bytes undecrypted at the end
        let end = (buf.len() / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
        match self.cbc_dec.decrypt_nopad(&mut buf[..end]) {
            Ok(_) => Some(end),
            Err(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sig_type_pad_len() {
        assert_eq!(SigType::DsaSha1.pad_len(EncType::ElGamal2048), 0);
        assert_eq!(SigType::EcdsaSha256P256.pad_len(EncType::ElGamal2048), 64);
        assert_eq!(SigType::EcdsaSha384P384.pad_len(EncType::ElGamal2048), 32);
        assert_eq!(SigType::EcdsaSha512P521.pad_len(EncType::ElGamal2048), 0);
        assert_eq!(SigType::Ed25519.pad_len(EncType::ElGamal2048), 96);
    }

    #[test]
    fn test_sig_type_extra_data_len() {
        assert_eq!(SigType::DsaSha1.extra_data_len(EncType::ElGamal2048), 0);
        assert_eq!(
            SigType::EcdsaSha256P256.extra_data_len(EncType::ElGamal2048),
            0
        );
        assert_eq!(
            SigType::EcdsaSha384P384.extra_data_len(EncType::ElGamal2048),
            0
        );
        assert_eq!(
            SigType::EcdsaSha512P521.extra_data_len(EncType::ElGamal2048),
            4
        );
        assert_eq!(SigType::Ed25519.extra_data_len(EncType::ElGamal2048), 0);
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

        for tv in test_vectors {
            let mut aes = Aes256::new(&tv.key, &tv.iv, &tv.iv);
            let mut blocks = tv.plaintext.clone();
            aes.encrypt_blocks(&mut blocks);
            assert_eq!(blocks, tv.ciphertext);
            aes.decrypt_blocks(&mut blocks);
            assert_eq!(blocks, tv.plaintext);
        }
    }
}
