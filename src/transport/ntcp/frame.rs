use cookie_factory::*;
use nom::{IResult, be_u16, be_u32};

use i2np::Message;
use i2np::frame::{gen_message, message};
use super::Frame;

//
// Utils
//

pub fn padding_len(content_len: usize) -> usize {
    ((16 - (content_len % 16) as u8) % 16) as usize
}

pub fn padding(input: &[u8], content_len: usize) -> IResult<&[u8], &[u8]> {
    take!(input, padding_len(content_len))
}

pub fn gen_padding<'a>(
    input: (&'a mut [u8], usize),
    content_len: usize,
) -> Result<(&'a mut [u8], usize), GenError> {
    let pad_len = padding_len(content_len);
    // TODO: Fill this with random padding
    gen_skip!(input, pad_len)
}

//
// Frames
//

// Adler-32 checksum as specified on https://tools.ietf.org/html/rfc1950#page-6
fn adler(input: &[u8]) -> [u8; 4] {
    let mut s1: u32 = 1;
    let mut s2: u32 = 0;
    for i in 0..input.len() {
        s1 += input[i] as u32;
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

named!(
    get_adler<[u8; 4]>,
    peek!(do_parse!(
        data:
            switch!(peek!(be_u16),
            0 => take!(12) |
            size => take!((size+2) as usize + padding_len((size+6) as usize))
        ) >> (adler(data))
    ))
);

fn gen_adler<'a>(
    input: (&'a mut [u8], usize),
    start: usize,
    end: usize,
) -> Result<(&'a mut [u8], usize), GenError> {
    let cs = adler(&input.0[start..end]);
    gen_slice!(input, cs)
}

// 0      2         size+2         12      size+6
// +------+------------+---------+-------+
// | size |    data    | padding | adler |
// +------+------------+---------+-------+
//  short  size octets     octets    octets

fn gen_standard_frame<'a>(
    input: (&'a mut [u8], usize),
    msg: &Message,
) -> Result<(&'a mut [u8], usize), GenError> {
    #[cfg_attr(rustfmt, rustfmt_skip)]
    do_gen!(
        input,
        start:     gen_skip!(2) >>
        msg_start: gen_message(msg) >>
        msg_end:   gen_at_offset!(start, gen_be_u16!(msg_end - msg_start)) >>
                   gen_padding(msg_end - msg_start + 6) >>
        end:       gen_adler(start, end)
    )
}

// 0     2           6         12      16
// +-----+-----------+---------+-------+
// |  0  | timestamp | padding | adler |
// +-----+-----------+---------+-------+
//  short    long      octets    octets

fn gen_timestamp_frame<'a>(
    input: (&'a mut [u8], usize),
    timestamp: u32,
) -> Result<(&'a mut [u8], usize), GenError> {
    #[cfg_attr(rustfmt, rustfmt_skip)]
    do_gen!(
        input,
        start: gen_be_u16!(0) >>
               gen_be_u32!(timestamp) >>
               gen_padding(10) >>
        end:   gen_adler(start, end)
    )
}

named!(pub frame<Frame>,
    do_parse!(
        cs: get_adler >>
        f: switch!(be_u16,
            0 => do_parse!(
                ts: be_u32 >>
                    take!(6) >>
                    tag!(cs) >>
                (Frame::TimeSync(ts))
            ) |
            size => do_parse!(
                msg: message >>
                     call!(padding, (size+6) as usize) >>
                     tag!(cs) >>
                (Frame::Standard(msg))
            )
        ) >>
        (f)
    )
);

pub fn gen_frame<'a>(
    input: (&'a mut [u8], usize),
    frame: &Frame,
) -> Result<(&'a mut [u8], usize), GenError> {
    match frame {
        &Frame::Standard(ref msg) => gen_standard_frame(input, &msg),
        &Frame::TimeSync(ts) => gen_timestamp_frame(input, ts),
    }
}

#[cfg(test)]
mod tests {
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
            IResult::Done(i, cs) => {
                assert_eq!(cs, &data[12..]);
            }
            IResult::Error(e) => {
                panic!("error in get_adler: {:?}", e);
            }
            IResult::Incomplete(n) => {
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
            IResult::Done(i, cs) => {
                assert_eq!(cs, &data[28..]);
            }
            IResult::Error(e) => {
                panic!("error in get_adler: {:?}", e);
            }
            IResult::Incomplete(n) => {
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
            IResult::Done(i, cs) => {
                assert_eq!(cs, &data[12..]);
            }
            IResult::Error(e) => {
                panic!("error in get_adler: {:?}", e);
            }
            IResult::Incomplete(n) => {
                panic!("incomplete get_adler: {:?}", n);
            }
        }
    }

    #[test]
    fn gen_timestamp_frame_valid() {
        let mut buf = vec![0u8; 16];
        match gen_timestamp_frame((&mut buf[..], 0), 12345678).map(|tup| tup.1) {
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
        match gen_timestamp_frame((&mut buf[..], 0), 12345678).map(|tup| tup.1) {
            Ok(sz) => {
                panic!("Returned {:?} bytes", sz);
            }
            Err(GenError::BufferTooSmall(sz)) => {
                // TODO: Figure out why this is 17, not 16
                assert_eq!(sz, 17);
            }
            Err(e) => {
                panic!("Unexpected error in gen_timestamp_frame: {:?}", e);
            }
        }
    }
}
