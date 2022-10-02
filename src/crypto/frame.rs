use std::{convert::TryInto, io::Write};

use cookie_factory::{bytes::be_u16 as gen_be_u16, combinator::slice as gen_slice, SerializeFn};
use nom::{
    bytes::streaming::take,
    combinator::{map, map_opt, map_res},
    error::{Error as NomError, ErrorKind},
    number::streaming::be_u16,
    IResult,
};

use crate::constants;
use crate::crypto::{
    EncType, PrivateKey, PublicKey, SessionKey, SigType, Signature, SigningPrivateKey,
    SigningPublicKey,
};

pub fn sig_type(i: &[u8]) -> IResult<&[u8], SigType> {
    map_opt(be_u16, |sig_type| match sig_type {
        constants::DSA_SHA1 => Some(SigType::DsaSha1),
        constants::ECDSA_SHA256_P256 => Some(SigType::EcdsaSha256P256),
        constants::ECDSA_SHA384_P384 => Some(SigType::EcdsaSha384P384),
        constants::ECDSA_SHA512_P521 => Some(SigType::EcdsaSha512P521),
        constants::RSA_SHA256_2048 => Some(SigType::Rsa2048Sha256),
        constants::RSA_SHA384_3072 => Some(SigType::Rsa3072Sha384),
        constants::RSA_SHA512_4096 => Some(SigType::Rsa4096Sha512),
        constants::ED25519 => Some(SigType::Ed25519),
        _ => None,
    })(i)
}

pub fn gen_sig_type<W: Write>(sig_type: SigType) -> impl SerializeFn<W> {
    gen_be_u16(sig_type.code())
}

pub fn enc_type(i: &[u8]) -> IResult<&[u8], EncType> {
    map_opt(be_u16, |enc_type| match enc_type {
        constants::ELGAMAL2048 => Some(EncType::ElGamal2048),
        _ => None,
    })(i)
}

pub fn gen_enc_type<W: Write>(enc_type: EncType) -> impl SerializeFn<W> {
    gen_be_u16(enc_type.code())
}

pub fn session_key(i: &[u8]) -> IResult<&[u8], SessionKey> {
    map(take(32usize), |k: &[u8]| {
        SessionKey::from_bytes(k.try_into().unwrap())
    })(i)
}

pub fn gen_session_key<'a, W: 'a + Write>(k: &SessionKey) -> impl SerializeFn<W> + 'a {
    gen_slice(k.0)
}

//
// Key material and signatures
//

// PublicKey

pub fn public_key(i: &[u8]) -> IResult<&[u8], PublicKey> {
    map(take(256usize), |k: &[u8]| {
        PublicKey::from_bytes(k.try_into().unwrap())
    })(i)
}

pub fn gen_public_key<'a, W: 'a + Write>(key: &PublicKey) -> impl SerializeFn<W> + 'a {
    gen_slice(key.0)
}

// PrivateKey

pub fn private_key(i: &[u8]) -> IResult<&[u8], PrivateKey> {
    map(take(256usize), |k: &[u8]| {
        PrivateKey::from_bytes(k.try_into().unwrap())
    })(i)
}

pub fn gen_private_key<'a, W: 'a + Write>(key: &PrivateKey) -> impl SerializeFn<W> + 'a {
    gen_slice(key.0)
}

// SigningPublicKey

pub fn signing_key(sig_type: SigType) -> impl Fn(&[u8]) -> IResult<&[u8], SigningPublicKey> {
    move |input: &[u8]| {
        map_res(take(sig_type.pubkey_len()), |sig_key| {
            SigningPublicKey::from_bytes(sig_type, sig_key)
        })(input)
    }
}

pub fn gen_signing_key<'a, W: 'a + Write>(key: &'a SigningPublicKey) -> impl SerializeFn<W> + 'a {
    gen_slice(key.as_bytes())
}

// SigningPrivateKey

pub fn signing_private_key(
    sig_type: SigType,
) -> impl Fn(&[u8]) -> IResult<&[u8], SigningPrivateKey> {
    move |input: &[u8]| {
        map_res(take(sig_type.pubkey_len()), |sig_key| {
            SigningPrivateKey::from_bytes(sig_type, sig_key)
        })(input)
    }
}

pub fn gen_signing_private_key<'a, W: 'a + Write>(
    key: &'a SigningPrivateKey,
) -> impl SerializeFn<W> + 'a {
    gen_slice(key.as_bytes())
}

// Signature

pub fn signature(sig_type: SigType) -> impl Fn(&[u8]) -> IResult<&[u8], Signature> {
    move |input: &[u8]| {
        map_res(take(sig_type.sig_len()), |sig| {
            Signature::from_bytes(sig_type, sig)
        })(input)
    }
}

pub fn gen_signature<'a, W: 'a + Write>(sig: &Signature) -> impl SerializeFn<W> + 'a {
    gen_slice(sig.to_bytes())
}
