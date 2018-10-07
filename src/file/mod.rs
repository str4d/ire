use nom::Err;

use crypto::Signature;
use data::RouterInfo;

mod frame;

const SU3_MAGIC: &[u8; 6] = b"I2Psu3";

#[derive(Debug)]
pub enum Su3Content {
    Reseed(Vec<RouterInfo>),
}

#[derive(Debug)]
pub struct Su3File {
    version: String,
    signer: String,
    pub content: Su3Content,
    sig: Signature,
}

impl Su3File {
    pub fn from_http_data(data: &[u8]) -> Result<Su3File, Err<&[u8]>> {
        let (data, _) = take_until!(data, &SU3_MAGIC[..])?;
        frame::su3_file(data).map(|(_, f)| f)
    }
}
