use cookie_factory::*;
use nom::{IResult, be_u16, be_u32};

use super::super::frame::{gen_padding, padding, padding_len};
use super::{HandshakeFrame, SessionConfirmA, SessionConfirmB, SessionCreated, SessionRequest};
use crypto::frame::{gen_signature, signature};
use data::frame::{gen_hash, gen_router_identity, hash, router_identity};
use data::{Hash, RouterIdentity};

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
        sig: call!(signature, &ri_b.signing_key.sig_type())
            >> take!(padding_len(ri_b.signing_key.sig_type().sig_len() as usize))
            >> (HandshakeFrame::SessionConfirmB(SessionConfirmB { sig }))
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
