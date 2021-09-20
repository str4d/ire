use cookie_factory::*;
use nom::sequence::{separated_pair, terminated};
use nom::IResult;
use nom::{
    bytes::streaming::take,
    combinator::map,
    number::streaming::{be_u16, be_u32},
    sequence::pair,
};

use super::super::frame::{gen_padding, padding, padding_len};
use super::{HandshakeFrame, SessionConfirmA, SessionConfirmB, SessionCreated, SessionRequest};
use crate::crypto::frame::{gen_signature, signature};
use crate::data::frame::{gen_hash, gen_router_identity, hash, router_identity};
use crate::data::{Hash, RouterIdentity};

//
// Handshake
//

// 0      256              288
// +-------+----------------+
// |   X   | H(X) ^ H(RI_B) |
// +-------+----------------+
//  octets       octets

pub fn session_request(i: &[u8]) -> IResult<&[u8], HandshakeFrame> {
    map(pair(take(256usize), hash), |(dh_x, hash)| {
        HandshakeFrame::SessionRequest(SessionRequest {
            dh_x: Vec::from(dh_x),
            hash,
        })
    })(i)
}

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

pub fn session_created_enc(i: &[u8]) -> IResult<&[u8], (Vec<u8>, Vec<u8>)> {
    map(pair(take(256usize), take(48usize)), |(dh_y, ct)| {
        (Vec::from(dh_y), Vec::from(ct))
    })(i)
}

pub fn gen_session_created_enc<'a>(
    input: (&'a mut [u8], usize),
    dh_y: &[u8],
    ct: &[u8; 48],
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(input, gen_slice!(dh_y) >> gen_slice!(ct))
}

// 0       32    36        48
// +-------+-----+---------+
// | H(XY) | tsB | padding |
// +-------+-----+---------+
//  octets  long   octets

pub fn session_created_dec(i: &[u8]) -> IResult<&[u8], (Hash, u32)> {
    terminated(pair(hash, be_u32), take(12usize))(i)
}

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
    dh_x: &[u8],
    dh_y: &[u8],
    ri: &RouterIdentity,
    ts_a: u32,
    ts_b: u32,
) -> Result<(&'a mut [u8], usize), GenError> {
    do_gen!(
        input,
        gen_slice!(dh_x)
            >> gen_slice!(dh_y)
            >> gen_hash(&ri.hash())
            >> gen_be_u32!(ts_a)
            >> gen_be_u32!(ts_b)
    )
}

pub fn session_confirm_a(i: &[u8]) -> IResult<&[u8], HandshakeFrame> {
    let (i, (size, ri_a)) = pair(be_u16, router_identity)(i)?;
    let (i, (ts_a, sig)) = separated_pair(
        be_u32,
        padding(size as usize + 6 + ri_a.signing_key.sig_type().sig_len() as usize),
        signature(ri_a.signing_key.sig_type()),
    )(i)?;
    Ok((
        i,
        HandshakeFrame::SessionConfirmA(SessionConfirmA { ri_a, ts_a, sig }),
    ))
}

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

pub fn session_confirm_b(
    ri_b: &RouterIdentity,
) -> impl Fn(&[u8]) -> IResult<&[u8], HandshakeFrame> {
    let sig_type = ri_b.signing_key.sig_type();
    move |input: &[u8]| {
        map(
            terminated(
                signature(sig_type),
                take(padding_len(sig_type.sig_len() as usize)),
            ),
            |sig| HandshakeFrame::SessionConfirmB(SessionConfirmB { sig }),
        )(input)
    }
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
