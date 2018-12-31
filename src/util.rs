//! Helper functions

use cookie_factory::GenError;
use core::fmt;
use std::iter::repeat;

pub fn serialize<S>(serializer: S) -> Vec<u8>
where
    S: Fn((&mut [u8], usize)) -> Result<(&mut [u8], usize), GenError>,
{
    let mut buf = vec![];
    loop {
        match serializer((&mut buf, 0)).map(|tup| tup.1) {
            Ok(sz) => {
                buf.truncate(sz);
                break;
            }
            Err(e) => match e {
                GenError::BufferTooSmall(sz) => {
                    let cur_len = buf.len();
                    buf.extend(repeat(0).take(sz - cur_len));
                }
                _ => panic!("Couldn't serialize"),
            },
        }
    }
    buf
}

/// Format a byte array as a colon-delimited hex string.
///
/// Source: https://github.com/tendermint/signatory
/// License: MIT / Apache 2.0
pub(crate) fn fmt_colon_delimited_hex<B>(f: &mut fmt::Formatter, bytes: B) -> fmt::Result
where
    B: AsRef<[u8]>,
{
    let len = bytes.as_ref().len();

    for (i, byte) in bytes.as_ref().iter().enumerate() {
        write!(f, "{:02x}", byte)?;

        if i != len - 1 {
            write!(f, ":")?;
        }
    }

    Ok(())
}
