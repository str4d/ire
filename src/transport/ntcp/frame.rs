use cookie_factory::*;
use nom::{IResult, be_u16, be_u32};

use crypto::frame::{gen_signature, signature};
use data::{Hash, RouterIdentity};
use data::frame::{gen_hash, gen_router_identity, hash, router_identity};
use i2np::Message;
use i2np::frame::{gen_message, message};
use super::{Frame, HandshakeFrame, SessionConfirmA, SessionConfirmB, SessionCreated,
            SessionRequest};

//
// Utils
//

fn padding_len(content_len: usize) -> usize {
    ((16 - (content_len % 16) as u8) % 16) as usize
}

fn padding(input: &[u8], content_len: usize) -> IResult<&[u8], &[u8]> {
    take!(input, padding_len(content_len))
}

fn gen_padding<'a>(
    input: (&'a mut [u8], usize),
    content_len: usize,
) -> Result<(&'a mut [u8], usize), GenError> {
    let pad_len = padding_len(content_len);
    // TODO: Fill this with random padding
    gen_skip!(input, pad_len)
}

//
// Handshake
//

// 0      256              288
// +-------+----------------+
// |   X   | H(X) ^ H(RI_B) |
// +-------+----------------+
//  octets       octets

named!(pub session_request<HandshakeFrame>,
    do_parse!(
        dh_x: take!(256) >>
        hash: hash >>
        (HandshakeFrame::SessionRequest(SessionRequest {
            dh_x: Vec::from(dh_x),
            hash: hash,
        }))
    )
);

pub fn gen_session_request<'a>(
    input: (&'a mut [u8], usize),
    sr: &SessionRequest,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(input, gen_slice!(sr.dh_x) >> gen_hash(&sr.hash))
}

// 0      256                  304
// +-------+--------------------+
// |   Y   | Encrypted contents |
// +-------+--------------------+
//  octets       octets

named!(pub session_created_enc<(Vec<u8>, Vec<u8>)>,
    do_parse!(
        dh_y: take!(256) >>
        ct:   take!(48)  >>
        ((Vec::from(dh_y), Vec::from(ct)))
    )
);

pub fn gen_session_created_enc<'a>(
    input: (&'a mut [u8], usize),
    dh_y: &Vec<u8>,
    ct: &[u8; 48],
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(input, gen_slice!(dh_y) >> gen_slice!(ct))
}

// 0       32    36        48
// +-------+-----+---------+
// | H(XY) | tsB | padding |
// +-------+-----+---------+
//  octets  long   octets

named!(pub session_created_dec<(Hash, u32)>,
    do_parse!(
        hash: hash >>
        ts_b: be_u32    >>
              take!(12) >>
        ((hash, ts_b ))
    )
);

pub fn gen_session_created_dec<'a>(
    input: (&'a mut [u8], usize),
    sc: &SessionCreated,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(
        input,
        gen_hash(&sc.hash) >> gen_be_u32!(sc.ts_b) >> gen_padding(36)
    )
}

// 0      2        sz+2  sz+6     sz+6+len(pad)   sz+6+len(pad)+len(sig)
// +------+---------+-----+------------+------------------------+
// |  sz  |  RI_A   | tsA |  padding   | S(X|Y|H(RI_B)|tsA|tsB) |
// +------+---------+-----+------------+------------------------+
//  short  sz octets long  0-15 octets
//
// - len(sig) is determined by RI_A
// - len(pad) is determined by rest of contents
// - Min RI length is 387 bytes, min sig length is 40 bytes (both for DSA)
//   - Therefore, min total message size is 448 bytes
// - RI cert type and length are in bytes 386-388
// - If there is a KeyCert, its types are in bytes 389-392
//   - If no KeyCert, these bytes will be tsA

pub fn gen_session_confirm_sig_msg<'a>(
    input: (&'a mut [u8], usize),
    dh_x: &Vec<u8>,
    dh_y: &Vec<u8>,
    ri: &RouterIdentity,
    ts_a: u32,
    ts_b: u32,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(
        input,
        gen_slice!(dh_x) >> gen_slice!(dh_y) >> gen_hash(&ri.hash()) >> gen_be_u32!(ts_a)
            >> gen_be_u32!(ts_b)
    )
}

named!(pub session_confirm_a<HandshakeFrame>,
    do_parse!(
        size:     be_u16 >>
        ri_a:     router_identity >>
        ts_a:     be_u32 >>
                  call!(padding,
                        size as usize + 6 + ri_a.signing_key.sig_type().sig_len() as usize) >>
        sig:      call!(signature, &ri_a.signing_key.sig_type()) >>
        (HandshakeFrame::SessionConfirmA(SessionConfirmA { ri_a, ts_a, sig }))
    )
);

pub fn gen_session_confirm_a<'a>(
    input: (&'a mut [u8], usize),
    sca: &SessionConfirmA,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(input,
        size:  gen_skip!(2) >>
        start: gen_router_identity(&sca.ri_a) >>
        end:   gen_at_offset!(size, gen_be_u16!(end-start)) >>
               gen_be_u32!(sca.ts_a) >>
               gen_padding(end - start + 6 + sca.ri_a.signing_key.sig_type().sig_len() as usize) >>
               gen_signature(&sca.sig)
    )
}

// 0
// +------------------------+---------+
// | S(X|Y|H(RI_A)|tsA|tsB) | padding |
// +------------------------+---------+
//          octets            octets
//
// Length determined by RI_B, which the recipient already knows.

pub fn session_confirm_b<'a>(
    input: &'a [u8],
    ri_b: &RouterIdentity,
) -> IResult<&'a [u8], HandshakeFrame> {
    do_parse!(
        input,
        sig: call!(signature, &ri_b.signing_key.sig_type()) >>
             take!(padding_len(ri_b.signing_key.sig_type().sig_len() as usize)) >>
        (HandshakeFrame::SessionConfirmB(SessionConfirmB { sig }))
    )
}

pub fn gen_session_confirm_b<'a>(
    input: (&'a mut [u8], usize),
    scb: &SessionConfirmB,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(input,
        start: gen_signature(&scb.sig) >>
        end:   gen_padding(end - start)
    )
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
        data: switch!(peek!(be_u16),
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
