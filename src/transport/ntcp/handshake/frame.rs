use std::io::Write;

use cookie_factory::{
    bytes::{be_u16 as gen_be_u16, be_u32 as gen_be_u32},
    combinator::{back_to_the_buffer, slice as gen_slice},
    gen, gen_simple,
    sequence::{pair as gen_pair, tuple as gen_tuple},
    Seek, SerializeFn, WriteContext,
};
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
use crate::data::frame::{gen_hash, gen_router_identity, hash, router_identity};
use crate::data::{Hash, RouterIdentity};
use crate::{
    crypto::frame::{gen_signature, signature},
    util::serialize,
};

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

pub fn gen_session_request<'a, W: 'a + Write>(sr: &'a SessionRequest) -> impl SerializeFn<W> + 'a {
    gen_pair(gen_slice(&sr.dh_x), gen_hash(&sr.hash))
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

pub fn gen_session_created_enc<'a, W: 'a + Write>(
    dh_y: &'a [u8],
    ct: &'a [u8; 48],
) -> impl SerializeFn<W> + 'a {
    gen_pair(gen_slice(dh_y), gen_slice(ct))
}

// 0       32    36        48
// +-------+-----+---------+
// | H(XY) | tsB | padding |
// +-------+-----+---------+
//  octets  long   octets

pub fn session_created_dec(i: &[u8]) -> IResult<&[u8], (Hash, u32)> {
    terminated(pair(hash, be_u32), take(12usize))(i)
}

pub fn gen_session_created_dec<'a, W: 'a + Write>(sc: &SessionCreated) -> impl SerializeFn<W> + 'a {
    gen_tuple((gen_hash(&sc.hash), gen_be_u32(sc.ts_b), gen_padding(36)))
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

pub fn gen_session_confirm_sig_msg<'a, W: 'a + Write>(
    dh_x: &'a [u8],
    dh_y: &'a [u8],
    ri: &RouterIdentity,
    ts_a: u32,
    ts_b: u32,
) -> impl SerializeFn<W> + 'a {
    gen_tuple((
        gen_slice(dh_x),
        gen_slice(dh_y),
        gen_hash(&ri.hash()),
        gen_be_u32(ts_a),
        gen_be_u32(ts_b),
    ))
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

pub fn gen_session_confirm_a<'a, W: 'a + Seek>(
    sca: &'a SessionConfirmA,
) -> impl SerializeFn<W> + 'a {
    back_to_the_buffer(
        2,
        move |buf| {
            let data = serialize(gen_router_identity(&sca.ri_a));
            let data_len = data.len();
            gen_simple(
                gen_tuple((
                    gen_slice(&data),
                    gen_be_u32(sca.ts_a),
                    gen_padding(data_len + 6 + sca.ri_a.signing_key.sig_type().sig_len() as usize),
                    gen_signature(&sca.sig),
                )),
                buf,
            )
            .map(|w| (w, data_len as u16))
        },
        move |buf, len| gen_simple(gen_be_u16(len), buf),
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

pub fn gen_session_confirm_b<'a, W: 'a + Write>(
    scb: &'a SessionConfirmB,
) -> impl SerializeFn<W> + 'a {
    move |w: WriteContext<W>| {
        let (w, len) = gen(gen_signature(&scb.sig), w)?;
        gen_padding(len as usize)(w)
    }
}
