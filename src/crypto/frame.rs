use cookie_factory::*;
use nom::{ErrorKind, IResult, be_u16};

use constants;
use crypto::{EncType, PrivateKey, PublicKey, SessionKey, SigType, Signature, SigningPrivateKey,
             SigningPublicKey};

named!(pub sig_type<SigType>,
    switch!(be_u16,
        constants::DSA_SHA1 => value!(SigType::DsaSha1) |
        constants::ECDSA_SHA256_P256 => value!(SigType::EcdsaSha256P256) |
        constants::ED25519 => value!(SigType::Ed25519)
    )
);

pub fn gen_sig_type<'a>(
    input: (&'a mut [u8], usize),
    sig_type: &SigType,
) -> Result<(&'a mut [u8], usize), GenError> {
    gen_be_u16!(input, sig_type.code())
}

named!(pub enc_type<EncType>,
    switch!(be_u16,
        constants::ELGAMAL2048 => value!(EncType::ElGamal2048)
    )
);

pub fn gen_enc_type<'a>(
    input: (&'a mut [u8], usize),
    enc_type: &EncType,
) -> Result<(&'a mut [u8], usize), GenError> {
    gen_be_u16!(input, enc_type.code())
}

named!(pub session_key<SessionKey>, do_parse!(
    k: take!(32) >> (SessionKey::from_bytes(array_ref![k, 0, 32]))
));

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

named!(pub public_key<PublicKey>, do_parse!(
    k: take!(256) >> (PublicKey::from_bytes(array_ref![k, 0, 256]))
));

pub fn gen_public_key<'a>(
    input: (&'a mut [u8], usize),
    key: &PublicKey,
) -> Result<(&'a mut [u8], usize), GenError> {
    gen_slice!(input, key.0)
}

// PrivateKey

named!(pub private_key<PrivateKey>, do_parse!(
    k: take!(256) >> (PrivateKey::from_bytes(array_ref![k, 0, 256]))
));

pub fn gen_private_key<'a>(
    input: (&'a mut [u8], usize),
    key: &PrivateKey,
) -> Result<(&'a mut [u8], usize), GenError> {
    gen_slice!(input, key.0)
}

// SigningPublicKey

pub fn signing_key<'a>(input: &'a [u8], sig_type: SigType) -> IResult<&'a [u8], SigningPublicKey> {
    match do_parse!(
        input,
        sig_key: take!(sig_type.pubkey_len()) >> (SigningPublicKey::from_bytes(&sig_type, sig_key))
    ) {
        IResult::Done(i, Ok(value)) => IResult::Done(i, value),
        IResult::Done(_, Err(_)) => IResult::Error(ErrorKind::Custom(1)),
        IResult::Error(e) => IResult::Error(e),
        IResult::Incomplete(l) => IResult::Incomplete(l),
    }
}

pub fn gen_signing_key<'a>(
    input: (&'a mut [u8], usize),
    key: &SigningPublicKey,
) -> Result<(&'a mut [u8], usize), GenError> {
    gen_slice!(input, key.as_bytes())
}

// SigningPrivateKey

pub fn signing_private_key<'a>(
    input: &'a [u8],
    sig_type: SigType,
) -> IResult<&'a [u8], SigningPrivateKey> {
    match do_parse!(
        input,
        sig_key: take!(sig_type.pubkey_len())
            >> (SigningPrivateKey::from_bytes(&sig_type, sig_key))
    ) {
        IResult::Done(i, Ok(value)) => IResult::Done(i, value),
        IResult::Done(_, Err(_)) => IResult::Error(ErrorKind::Custom(1)),
        IResult::Error(e) => IResult::Error(e),
        IResult::Incomplete(l) => IResult::Incomplete(l),
    }
}

pub fn gen_signing_private_key<'a>(
    input: (&'a mut [u8], usize),
    key: &SigningPrivateKey,
) -> Result<(&'a mut [u8], usize), GenError> {
    gen_slice!(input, key.as_bytes())
}

// Signature

pub fn signature<'a>(input: &'a [u8], sig_type: &SigType) -> IResult<&'a [u8], Signature> {
    match do_parse!(
        input,
        sig: take!(sig_type.sig_len()) >> (Signature::from_bytes(sig_type, sig))
    ) {
        IResult::Done(i, Ok(value)) => IResult::Done(i, value),
        IResult::Done(_, Err(_)) => IResult::Error(ErrorKind::Custom(1)),
        IResult::Error(e) => IResult::Error(e),
        IResult::Incomplete(l) => IResult::Incomplete(l),
    }
}

pub fn gen_signature<'a>(
    input: (&'a mut [u8], usize),
    sig: &Signature,
) -> Result<(&'a mut [u8], usize), GenError> {
    gen_slice!(input, sig.to_bytes())
}
