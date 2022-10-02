use std::io::Write;

use cookie_factory::{
    bytes::{be_u16 as gen_be_u16, be_u32 as gen_be_u32, be_u8 as gen_be_u8},
    combinator::back_to_the_buffer,
    combinator::{skip as gen_skip, slice as gen_slice},
    gen, gen_simple,
    multi::all as gen_all,
    sequence::{pair as gen_pair, tuple as gen_tuple},
    Seek, SerializeFn, WriteContext,
};
use nom::{
    bytes::streaming::{tag, take},
    combinator::{map, peek, success},
    multi::length_value,
    number::streaming::{be_u16, be_u32},
    sequence::{pair, terminated},
    IResult,
};
use rand::{rngs::OsRng, Rng};

use super::Frame;
use crate::i2np::Message;
use crate::{
    i2np::frame::{gen_message, message},
    util::serialize,
};

//
// Utils
//

pub fn padding_len(content_len: usize) -> usize {
    ((16 - (content_len % 16) as u8) % 16) as usize
}

pub fn padding(content_len: usize) -> impl Fn(&[u8]) -> IResult<&[u8], &[u8]> {
    move |i: &[u8]| take(padding_len(content_len))(i)
}

pub fn gen_padding<W: Write>(content_len: usize) -> impl SerializeFn<W> {
    let pad_len = padding_len(content_len);
    gen_all((0..pad_len).map(|_| OsRng.gen()).map(gen_be_u8))
}

//
// Frames
//

// Adler-32 checksum as specified on https://tools.ietf.org/html/rfc1950#page-6
fn adler(input: &[u8]) -> [u8; 4] {
    let mut s1: u32 = 1;
    let mut s2: u32 = 0;
    for x in input {
        s1 += u32::from(*x);
        s1 %= 65521;
        s2 += s1;
        s2 %= 65521;
    }
    [
        ((s2 >> 8) & 0xff) as u8,
        (s2 & 0xff) as u8,
        ((s1 >> 8) & 0xff) as u8,
        (s1 & 0xff) as u8,
    ]
}

fn get_adler(input: &[u8]) -> IResult<&[u8], [u8; 4]> {
    let (i, sz) = peek(be_u16)(input)?;
    let (i, data) = match sz {
        0 => take(12usize)(i),
        size => take((size + 2) as usize + padding_len((size + 6) as usize))(i),
    }?;
    // Return the original input, as if we wrapped this in peek().
    Ok((input, adler(data)))
}

fn gen_adler<W: Write>(content: &[u8]) -> impl SerializeFn<W> {
    let cs = adler(content);
    gen_slice(cs)
}

// 0      2         size+2         12      size+6
// +------+------------+---------+-------+
// | size |    data    | padding | adler |
// +------+------------+---------+-------+
//  short  size octets     octets    octets

fn gen_standard_frame<'a, W: 'a + Seek>(msg: &'a Message) -> impl SerializeFn<W> + 'a {
    move |w: WriteContext<W>| {
        let content = serialize(back_to_the_buffer(
            2,
            move |buf| {
                let data = serialize(gen_message(msg));
                let data_len = data.len();
                gen_simple(
                    gen_tuple((gen_slice(&data), gen_padding(data_len + 6))),
                    buf,
                )
                .map(|w| (w, data_len))
            },
            move |buf, data_len| gen_simple(gen_be_u16(data_len as u16), buf),
        ));
        gen_simple(gen_pair(gen_slice(&content), gen_adler(&content)), w)
    }
}

// 0     2           6         12      16
// +-----+-----------+---------+-------+
// |  0  | timestamp | padding | adler |
// +-----+-----------+---------+-------+
//  short    long      octets    octets

fn gen_timestamp_frame<W: Write>(timestamp: u32) -> impl SerializeFn<W> {
    move |w: WriteContext<W>| {
        let data = serialize(gen_tuple((
            gen_be_u16(0),
            gen_be_u32(timestamp),
            gen_padding(10),
        )));
        gen_simple(gen_pair(gen_slice(&data), gen_adler(&data)), w)
    }
}

pub fn frame(i: &[u8]) -> IResult<&[u8], Frame> {
    let (i, (cs, sz)) = pair(get_adler, be_u16)(i)?;
    match sz {
        0 => map(
            terminated(be_u32, pair(take(6usize), tag(cs))),
            Frame::TimeSync,
        )(i),
        size => map(
            terminated(
                length_value(success(size), message),
                pair(padding((size + 6) as usize), tag(cs)),
            ),
            Frame::Standard,
        )(i),
    }
}

pub fn gen_frame<'a, W: 'a + Seek>(frame: &'a Frame) -> impl SerializeFn<W> + 'a {
    move |w: WriteContext<W>| match frame {
        Frame::Standard(msg) => gen_standard_frame(msg)(w),
        Frame::TimeSync(ts) => gen_timestamp_frame(*ts)(w),
    }
}

#[cfg(test)]
mod tests {
    use nom::Err;

    use super::*;

    #[test]
    fn test_adler() {
        // From http://wiki.hping.org/124
        assert_eq!([0x13, 0x07, 0x03, 0x94], adler(&b"Mark Adler"[..]));
        assert_eq!([0x00, 0x0e, 0x00, 0x07], adler(&[0x00, 0x01, 0x02, 0x03]));
        assert_eq!(
            [0x00, 0x5c, 0x00, 0x1d],
            adler(&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07])
        );
        assert_eq!(
            [0x02, 0xb8, 0x00, 0x79],
            adler(&[
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f,
            ])
        );
        assert_eq!([0x02, 0x8e, 0x01, 0x05], adler(&[0x41, 0x41, 0x41, 0x41]));
        assert_eq!(
            [0x09, 0x50, 0x02, 0x11],
            adler(&[0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42])
        );
        assert_eq!(
            [0x23, 0xa8, 0x04, 0x31],
            adler(&[
                0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43,
                0x43, 0x43,
            ])
        );
        // From https://github.com/froydnj/ironclad/blob/master/testing/test-vectors/adler32.testvec
        assert_eq!([0x00, 0x00, 0x00, 0x01], adler(&b""[..]));
        assert_eq!([0x00, 0x62, 0x00, 0x62], adler(&b"a"[..]));
        assert_eq!([0x02, 0x4d, 0x01, 0x27], adler(&b"abc"[..]));
        assert_eq!([0x29, 0x75, 0x05, 0x86], adler(&b"message digest"[..]));
        assert_eq!(
            [0x90, 0x86, 0x0b, 0x20],
            adler(&b"abcdefghijklmnopqrstuvwxyz"[..])
        );
        assert_eq!(
            [0x8a, 0xdb, 0x15, 0x0c],
            adler(&b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"[..])
        );
        assert_eq!([0x97, 0xb6, 0x10, 0x69],
            adler(&b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"[..]));
    }

    #[test]
    fn get_adler_standard() {
        let data = [
            0x00, 0x02, 0x01, 0x02, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0xb6,
            0x00, 0x2a,
        ];
        match get_adler(&data) {
            Ok((_, cs)) => {
                assert_eq!(cs, &data[12..]);
            }
            Err(Err::Error(e)) | Err(Err::Failure(e)) => {
                panic!("error in get_adler: {:?}", e);
            }
            Err(Err::Incomplete(n)) => {
                panic!("incomplete get_adler: {:?}", n);
            }
        }
    }

    #[test]
    fn get_adler_standard_long() {
        let data = [
            0x00, 0x10, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
            0x0d, 0x0e, 0x0f, 0x10, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
            0x0b, 0x28, 0x00, 0xd0,
        ];
        match get_adler(&data) {
            Ok((_, cs)) => {
                assert_eq!(cs, &data[28..]);
            }
            Err(Err::Error(e)) | Err(Err::Failure(e)) => {
                panic!("error in get_adler: {:?}", e);
            }
            Err(Err::Incomplete(n)) => {
                panic!("incomplete get_adler: {:?}", n);
            }
        }
    }

    #[test]
    fn get_adler_timesync() {
        let data = [
            0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x94,
            0x00, 0x20,
        ];
        match get_adler(&data) {
            Ok((_, cs)) => {
                assert_eq!(cs, &data[12..]);
            }
            Err(Err::Error(e)) | Err(Err::Failure(e)) => {
                panic!("error in get_adler: {:?}", e);
            }
            Err(Err::Incomplete(n)) => {
                panic!("incomplete get_adler: {:?}", n);
            }
        }
    }

    #[test]
    fn gen_timestamp_frame_valid() {
        let mut buf = vec![0u8; 16];
        match gen_timestamp_frame((&mut buf[..], 0), 12_345_678).map(|tup| tup.1) {
            Ok(sz) => {
                assert_eq!(sz, 16);
                assert_eq!(&buf[0..2], &[0x00, 0x00]);
                assert_eq!(&buf[2..6], &[0x00, 0xbc, 0x61, 0x4e]);
            }
            Err(e) => {
                panic!("error in gen_timestamp_frame: {:?}", e);
            }
        }
    }

    #[test]
    fn gen_timestamp_frame_small_buffer() {
        let mut buf = vec![0u8; 12];
        match gen_timestamp_frame((&mut buf[..], 0), 12_345_678).map(|tup| tup.1) {
            Ok(sz) => {
                panic!("Returned {:?} bytes", sz);
            }
            Err(GenError::BufferTooSmall(sz)) => {
                assert_eq!(sz, 16);
            }
            Err(e) => {
                panic!("Unexpected error in gen_timestamp_frame: {:?}", e);
            }
        }
    }
}
