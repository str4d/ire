use std::convert::TryInto;

use cookie_factory::*;
use nom::*;
use nom::{
    bytes::streaming::take,
    combinator::{map, map_opt, map_res},
    error::{Error as NomError, ErrorKind},
    number::streaming::be_u16,
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

pub fn gen_sig_type(
    input: (&mut [u8], usize),
    sig_type: SigType,
) -> Result<(&mut [u8], usize), GenError> {
    gen_be_u16!(input, sig_type.code())
}

pub fn enc_type(i: &[u8]) -> IResult<&[u8], EncType> {
    map_opt(be_u16, |enc_type| match enc_type {
        constants::ELGAMAL2048 => Some(EncType::ElGamal2048),
        _ => None,
    })(i)
}

pub fn gen_enc_type(
    input: (&mut [u8], usize),
    enc_type: EncType,
) -> Result<(&mut [u8], usize), GenError> {
    gen_be_u16!(input, enc_type.code())
}

pub fn session_key(i: &[u8]) -> IResult<&[u8], SessionKey> {
    map(take(32usize), |k: &[u8]| {
        SessionKey::from_bytes(k.try_into().unwrap())
    })(i)
}

pub fn gen_session_key<'a>(
    input: (&'a mut [u8], usize),
    k: &SessionKey,
) -> Result<(&'a mut [u8], usize), GenError> {
    gen_slice!(input, k.0)
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

pub fn gen_public_key<'a>(
    input: (&'a mut [u8], usize),
    key: &PublicKey,
) -> Result<(&'a mut [u8], usize), GenError> {
    gen_slice!(input, key.0)
}

// PrivateKey

pub fn private_key(i: &[u8]) -> IResult<&[u8], PrivateKey> {
    map(take(256usize), |k: &[u8]| {
        PrivateKey::from_bytes(k.try_into().unwrap())
    })(i)
}

pub fn gen_private_key<'a>(
    input: (&'a mut [u8], usize),
    key: &PrivateKey,
) -> Result<(&'a mut [u8], usize), GenError> {
    gen_slice!(input, key.0)
}

// SigningPublicKey

pub fn signing_key(input: &[u8], sig_type: SigType) -> IResult<&[u8], SigningPublicKey> {
    match do_parse!(
        input,
        sig_key: take!(sig_type.pubkey_len()) >> (SigningPublicKey::from_bytes(sig_type, sig_key))
    )? {
        (i, Ok(value)) => Ok((i, value)),
        (_, Err(_)) => Err(Err::Error(NomError::new(input, ErrorKind::Verify))),
    }
}

pub fn gen_signing_key<'a>(
    input: (&'a mut [u8], usize),
    key: &SigningPublicKey,
) -> Result<(&'a mut [u8], usize), GenError> {
    gen_slice!(input, key.as_bytes())
}

// SigningPrivateKey

pub fn signing_private_key(input: &[u8], sig_type: SigType) -> IResult<&[u8], SigningPrivateKey> {
    match do_parse!(
        input,
        sig_key: take!(sig_type.pubkey_len()) >> (SigningPrivateKey::from_bytes(sig_type, sig_key))
    )? {
        (i, Ok(value)) => Ok((i, value)),
        (_, Err(_)) => Err(Err::Error(NomError::new(input, ErrorKind::Verify))),
    }
}

pub fn gen_signing_private_key<'a>(
    input: (&'a mut [u8], usize),
    key: &SigningPrivateKey,
) -> Result<(&'a mut [u8], usize), GenError> {
    gen_slice!(input, key.as_bytes())
}

// Signature

pub fn signature(input: &[u8], sig_type: SigType) -> IResult<&[u8], Signature> {
    match do_parse!(
        input,
        sig: take!(sig_type.sig_len()) >> (Signature::from_bytes(sig_type, sig))
    )? {
        (i, Ok(value)) => Ok((i, value)),
        (_, Err(_)) => Err(Err::Error(NomError::new(input, ErrorKind::Verify))),
    }
}

pub fn gen_signature<'a>(
    input: (&'a mut [u8], usize),
    sig: &Signature,
) -> Result<(&'a mut [u8], usize), GenError> {
    gen_slice!(input, sig.to_bytes())
}
