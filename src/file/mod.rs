use nom;
use std::collections::HashMap;

use crypto::{self, OfflineSigningPublicKey, SigType, Signature};
use data::{ReadError, RouterInfo};

mod frame;

const SU3_MAGIC: &[u8; 6] = b"I2Psu3";

/// SU3 errors
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Crypto(crypto::Error),
    Read(ReadError),
    UnknownSigner,
}

impl From<crypto::Error> for Error {
    fn from(e: crypto::Error) -> Self {
        Error::Crypto(e)
    }
}

impl<T> From<nom::Err<T>> for Error {
    fn from(e: nom::Err<T>) -> Self {
        Error::Read(e.into())
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
    pub fn from_http_data(
        input: &[u8],
        signers: &HashMap<&'static str, OfflineSigningPublicKey>,
    ) -> Result<Su3File, Error> {
        let (data, _) = take_until!(input, &SU3_MAGIC[..])?;
        Su3File::from_bytes(data, signers)
    }

    pub fn from_bytes(
        data: &[u8],
        signers: &HashMap<&'static str, OfflineSigningPublicKey>,
    ) -> Result<Su3File, Error> {
        let (_, su3_file) = frame::su3_file(data)?;

        // Verify the SU3 file signature
        if let Some(pk) = signers.get(&su3_file.signer.as_str()) {
            pk.verify(&data[..su3_file.msg_len], &su3_file.sig)?;
        } else {
            return Err(Error::UnknownSigner);
        }

        Ok(su3_file)
    }
}

#[cfg(test)]
mod tests {
    use super::{Su3Content, Su3File};
    use crypto::SigType;
    use netdb::reseed::RESEED_SIGNERS;
    use tests::I2PSEEDS_SU3;

    #[test]
    fn reseed_file() {
        match Su3File::from_bytes(I2PSEEDS_SU3, &RESEED_SIGNERS) {
            Ok(su3_file) => {
                assert_eq!(su3_file.version, "1539145006");
                assert_eq!(su3_file.signer, "meeh@mail.i2p");
                match su3_file.content {
                    Su3Content::Reseed(ri) => assert_eq!(ri.len(), 75),
                }
                assert_eq!(su3_file.sig_type, SigType::Rsa4096Sha512);
            }
            Err(e) => panic!("Error while parsing reseed file: {:?}", e),
        }
    }
}
