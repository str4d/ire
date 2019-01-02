//! Helper functions

use cookie_factory::GenError;
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
