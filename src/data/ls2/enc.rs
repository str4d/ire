//! Encryption mechanism for lease information in the network database.
//!
//! Blinding is used to enforce that only clients with knowledge of the
//! Destination can decrypt the lease information.

use byteorder::{BigEndian, WriteBytesExt};
use c2_chacha::{
    stream_cipher::{NewStreamCipher, SyncStreamCipher, SyncStreamCipherSeek},
    Ietf as ChaCha20Ietf,
};
use hkdf::Hkdf;
use rand::{rngs::OsRng, Rng};
use sha2::{Digest, Sha256};
use std::fmt;

use super::{LeaseSet2, MetaLeaseSet2, TransientSigningPublicKey};
use crate::crypto::{self, Signature, SigningPrivateKey, SigningPublicKey};
use crate::util::serialize;

pub mod auth;
pub(crate) mod frame;

const SALT_LEN: usize = 16;
const S_KEY_LEN: usize = 32;
const S_IV_LEN: usize = 12;

const LAYER_1_INFO: &[u8; 8] = b"ELS2_L1K";
const LAYER_2_INFO: &[u8; 8] = b"ELS2_L2K";

/// Network database store errors
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Crypto(crypto::Error),
    InvalidClientAuth,
    InvalidPayload,
    NotAuthorised,
}

impl From<crypto::Error> for Error {
    fn from(e: crypto::Error) -> Self {
        Error::Crypto(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Crypto(e) => e.fmt(f),
            Error::InvalidClientAuth => "Client authentication layer is invalid".fmt(f),
            Error::InvalidPayload => "Payload is invalid".fmt(f),
            Error::NotAuthorised => "Not authorised to decrypt EncLS2".fmt(f),
        }
    }
}

fn kdf(
    secret_value: &[u8],
    subcredential: &[u8],
    created: u32,
    salt: &[u8],
    info: &[u8],
    okm: &mut [u8],
) {
    let mut ikm = Vec::new();
    ikm.extend_from_slice(secret_value);
    ikm.extend_from_slice(subcredential);
    (&mut ikm).write_u32::<BigEndian>(created).unwrap();

    Hkdf::<Sha256>::extract(Some(&salt), &ikm)
        .expand(info, okm)
        .unwrap();
}

fn stream_cipher(key: &[u8], iv: &[u8], input: &[u8], output: &mut [u8]) {
    assert_eq!(input.len(), output.len());
    output.copy_from_slice(input);
    let mut chacha20 = ChaCha20Ietf::new_var(key, iv).unwrap();
    // Skip the first block of output
    chacha20.seek(64);
    chacha20.apply_keystream(output);
}

struct Encryptor;

impl Encryptor {
    fn encrypt(
        auth_cookie: &[u8],
        subcredential: &[u8],
        created: u32,
        info: &[u8],
        plaintext: &[u8],
    ) -> Vec<u8> {
        assert!(!plaintext.is_empty());
        let mut ciphertext = Vec::new();
        ciphertext.resize(plaintext.len() + SALT_LEN, 0);

        // Generate a random salt, placing it at the start of the ciphertext
        let mut rng = OsRng::new().unwrap();
        rng.fill(&mut ciphertext[0..SALT_LEN]);

        // Derive the encryption key and IV
        let mut okm = [0; S_KEY_LEN + S_IV_LEN];
        kdf(
            auth_cookie,
            subcredential,
            created,
            &ciphertext[0..SALT_LEN],
            info,
            &mut okm,
        );
        let key = &okm[0..S_KEY_LEN];
        let iv = &okm[S_KEY_LEN..S_KEY_LEN + S_IV_LEN];

        // Encrypt the plaintext into the ciphertext buffer, following the salt
        stream_cipher(key, iv, plaintext, &mut ciphertext[SALT_LEN..]);
        ciphertext
    }

    fn decrypt(
        auth_cookie: &[u8],
        subcredential: &[u8],
        created: u32,
        info: &[u8],
        ciphertext: &[u8],
    ) -> Vec<u8> {
        // Slice the salt out of the ciphertext
        assert!(ciphertext.len() > SALT_LEN);
        let salt = &ciphertext[0..SALT_LEN];

        // Derive the encryption key and IV
        let mut okm = [0; S_KEY_LEN + S_IV_LEN];
        kdf(auth_cookie, subcredential, created, salt, info, &mut okm);
        let key = &okm[0..S_KEY_LEN];
        let iv = &okm[S_KEY_LEN..S_KEY_LEN + S_IV_LEN];

        // Decrypt the plaintext from the second half of the ciphertext
        let mut plaintext = Vec::new();
        plaintext.resize(ciphertext.len() - SALT_LEN, 0);
        stream_cipher(key, iv, &ciphertext[SALT_LEN..], &mut plaintext);
        plaintext
    }
}

/// The inner payload of an encrypted LS2.
pub enum EncLS2Payload {
    LS2(LeaseSet2),
    MetaLS2(MetaLeaseSet2),
}

impl EncLS2Payload {
    fn decrypt(
        auth_cookie: &[u8],
        subcredential: &[u8],
        created: u32,
        ciphertext: &[u8],
    ) -> Result<Self, Error> {
        let plaintext = Encryptor::decrypt(
            auth_cookie,
            subcredential,
            created,
            LAYER_2_INFO,
            ciphertext,
        );
        match frame::enc_ls2_payload(&plaintext) {
            Ok((_, ret)) => Ok(ret),
            Err(_) => Err(Error::InvalidPayload),
        }
    }

    fn encrypt(&self, auth_cookie: &[u8], subcredential: &[u8], created: u32) -> Vec<u8> {
        let plaintext = serialize(|input| frame::gen_enc_ls2_payload(input, self));
        Encryptor::encrypt(
            auth_cookie,
            subcredential,
            created,
            LAYER_2_INFO,
            &plaintext,
        )
    }
}

/// Client authentication layer inside an encrypted LS2.
#[derive(Debug, PartialEq)]
pub(crate) struct EncLS2ClientAuth {
    auth_data: Option<auth::ClientAuthType>,
    inner_ciphertext: Vec<u8>,
}

impl EncLS2ClientAuth {
    fn decrypt(subcredential: &[u8], created: u32, ciphertext: &[u8]) -> Result<Self, Error> {
        let plaintext = Encryptor::decrypt(&[], subcredential, created, LAYER_1_INFO, ciphertext);
        match frame::enc_ls2_client_auth(&plaintext) {
            Ok((_, ret)) => Ok(ret),
            Err(_) => Err(Error::InvalidClientAuth),
        }
    }

    fn encrypt(&self, subcredential: &[u8], created: u32) -> Vec<u8> {
        let plaintext = serialize(|input| frame::gen_enc_ls2_client_auth(input, self));
        Encryptor::encrypt(&[], subcredential, created, LAYER_1_INFO, &plaintext)
    }
}

/// Encrypted and blinded lease information.
pub struct EncryptedLS2 {
    blinded_key: SigningPublicKey,
    created: u32,
    expires: u16,
    transient: Option<TransientSigningPublicKey>,
    outer_ciphertext: Vec<u8>,
    signature: Option<Signature>,
}

impl EncryptedLS2 {
    pub fn encrypt_payload(
        payload: &EncLS2Payload,
        credential: &[u8],
        blinded_key: SigningPublicKey,
        transient: Option<TransientSigningPublicKey>,
        sig_key: &SigningPrivateKey,
        client_info: Option<auth::ClientInfo>,
    ) -> Result<Self, Error> {
        // Signing key must correctly match either the blinded key or the transient key
        if let Some(ref transient) = transient {
            assert_eq!(SigningPublicKey::from_secret(&sig_key)?, transient.pubkey);
        } else {
            assert_eq!(SigningPublicKey::from_secret(&sig_key)?, blinded_key);
        }

        // Outer timestamp and expiration must match payload
        let (created, expires) = match payload {
            EncLS2Payload::LS2(ls2) => (ls2.header.created, ls2.header.expires),
            EncLS2Payload::MetaLS2(meta_ls2) => (meta_ls2.header.created, meta_ls2.header.expires),
        };

        // Compute subcredential
        // TODO: Should `blinded_key.as_bytes()` include the type?
        let subcredential = Sha256::default()
            .chain(b"subcredential")
            .chain(credential)
            .chain(blinded_key.as_bytes())
            .result();

        // Handle client authentication
        let (auth_cookie, auth_data) =
            auth::ClientAuthType::from_info(client_info, subcredential.as_slice(), created);

        // Encrypt layer 2
        let inner_ciphertext = payload.encrypt(&auth_cookie, subcredential.as_slice(), created);

        // Create layer 1
        let client_auth = EncLS2ClientAuth {
            auth_data,
            inner_ciphertext,
        };

        // Encrypt layer 1
        let outer_ciphertext = client_auth.encrypt(subcredential.as_slice(), created);

        // Create layer 0
        let mut enc_ls2 = EncryptedLS2 {
            blinded_key,
            created,
            expires,
            transient,
            outer_ciphertext,
            signature: None,
        };
        let msg = serialize(|input| frame::gen_encrypted_ls2_signed_msg(input, &enc_ls2));
        enc_ls2.signature = Some(sig_key.sign(&msg)?);

        Ok(enc_ls2)
    }

    pub fn decrypt(
        &self,
        credential: &[u8],
        auth_key: Option<&auth::ClientSecretKey>,
    ) -> Result<EncLS2Payload, Error> {
        // Always validate the signature first, to ensure ciphertext is unmodified.
        if let Some(ref signature) = self.signature {
            let msg = serialize(|input| frame::gen_encrypted_ls2_signed_msg(input, self));
            if let Some(ref transient) = self.transient {
                transient.pubkey.verify(&msg, signature)?;
            } else {
                self.blinded_key.verify(&msg, signature)?;
            }
        } else {
            return Err(Error::Crypto(crypto::Error::NoSignature));
        }

        // Compute subcredential
        let subcredential = Sha256::default()
            .chain(b"subcredential")
            .chain(credential)
            .chain(self.blinded_key.as_bytes())
            .result();

        // Decrypt layer 1
        let client_auth = EncLS2ClientAuth::decrypt(
            subcredential.as_slice(),
            self.created,
            &self.outer_ciphertext,
        )?;

        // Handle client authentication
        let auth_cookie = match (client_auth.auth_data, auth_key) {
            (Some(auth_data), Some(key)) => {
                auth_data.authenticate(key, subcredential.as_slice(), self.created)?
            }
            (Some(_), None) => return Err(Error::NotAuthorised),
            (None, _) => vec![],
        };

        // Decrypt layer 2
        EncLS2Payload::decrypt(
            &auth_cookie,
            subcredential.as_slice(),
            self.created,
            &client_auth.inner_ciphertext,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{EncLS2Payload, EncryptedLS2, Encryptor};
    use crate::crypto::{SigningPrivateKey, SigningPublicKey};
    use crate::data::{dest::DestinationSecretKeys, ls2::LeaseSet2};

    #[test]
    fn encryptor_round_trip() {
        let subcredential = b"subcredential";
        let auth_cookie = b"auth_cookie";
        let info = b"info";
        let plaintext = b"plaintext";

        let ciphertext = Encryptor::encrypt(subcredential, auth_cookie, 0, info, plaintext);

        assert_eq!(
            Encryptor::decrypt(subcredential, auth_cookie, 0, info, &ciphertext),
            plaintext
        );
    }

    fn fake_ls2(created: u32, expires: u16) -> LeaseSet2 {
        let (dest, ls2_sigkey) = {
            let dsk = DestinationSecretKeys::new();
            (dsk.dest, dsk.signing_private_key)
        };

        let mut ls2 = LeaseSet2::new(dest, created, expires, None);
        ls2.sign(&ls2_sigkey).unwrap();
        ls2
    }

    #[test]
    fn enc_ls2_round_trip() {
        let ls2 = fake_ls2(123_456_789, 2345);

        let payload = EncLS2Payload::LS2(ls2);
        let credential = b"credential";

        let blinded_privkey = SigningPrivateKey::new();
        let blinded_pubkey = SigningPublicKey::from_secret(&blinded_privkey).unwrap();

        // Encrypt the payload with client authorization disabled
        let enc_ls2 = EncryptedLS2::encrypt_payload(
            &payload,
            credential,
            blinded_pubkey,
            None,
            &blinded_privkey,
            None,
        )
        .unwrap();

        // Can decrypt without any client key
        match enc_ls2.decrypt(credential, None).unwrap() {
            EncLS2Payload::LS2(decrypted_ls2) => {
                assert_eq!(decrypted_ls2.header.created, 123_456_789);
                assert_eq!(decrypted_ls2.header.expires, 2345);
                assert!(decrypted_ls2.header.transient.is_none());
                assert!(!decrypted_ls2.header.published);
                assert!(decrypted_ls2.enc_keys.is_empty());
                assert!(decrypted_ls2.leases.is_empty());
                assert!(decrypted_ls2.signature.is_some());
            }
            _ => panic!(),
        }
    }
}
