use nom;
use std::collections::HashMap;

use crypto::{self, OfflineSigningPublicKey, SigType, Signature};
use data::RouterInfo;

mod frame;

const SU3_MAGIC: &[u8; 6] = b"I2Psu3";

/// SU3 errors
#[derive(Debug)]
pub enum Error<'a> {
    Nom(nom::Err<&'a [u8]>),
    UnknownSigner,
    InvalidSignature(crypto::Error),
}

impl<'a> From<nom::Err<&'a [u8]>> for Error<'a> {
    fn from(e: nom::Err<&'a [u8]>) -> Self {
        Error::Nom(e)
    }
}

#[derive(Debug)]
pub enum Su3Content {
    Reseed(Vec<RouterInfo>),
}

#[derive(Debug)]
pub struct Su3File {
    version: String,
    signer: String,
    pub content: Su3Content,
    sig_type: SigType,
    msg_len: usize,
    sig: Signature,
}

impl Su3File {
    pub fn from_http_data<'a>(
        input: &'a [u8],
        signers: &HashMap<&'static str, OfflineSigningPublicKey>,
    ) -> Result<Su3File, Error<'a>> {
        let (data, _) = take_until!(input, &SU3_MAGIC[..])?;
        let (_, su3_file) = frame::su3_file(data)?;

        // Verify the SU3 file signature
        match if let Some(pk) = signers.get(&su3_file.signer.as_str()) {
            pk.verify(&data[..su3_file.msg_len], &su3_file.sig)
                .map_err(|e| Error::InvalidSignature(e))
        } else {
            Err(Error::UnknownSigner)
        } {
            Ok(()) => Ok(su3_file),
            Err(e) => Err(e),
        }
    }
}
