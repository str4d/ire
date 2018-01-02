use actix::prelude::*;
use cookie_factory::GenError;
use bytes::BytesMut;
use futures::{future, Future};
use nom::{IResult, Offset};
use std::io;
use std::iter::repeat;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::ops::AddAssign;
use std::process;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio_core::net::TcpStream;
use tokio_core::reactor::Timeout;
use tokio_io::codec::{Decoder, Encoder, Framed};

use crypto::{Aes256, Signature, SigningPrivateKey, AES_BLOCK_SIZE};
use data::{Hash, RouterIdentity};
use i2np::Message;
use super::{DHSessionKeyBuilder, TcpConnect};

mod frame;

// Max NTCP message size is 16kB
const NTCP_MTU: usize = 16384;

//
// Establishment handshake
//

pub struct SessionRequest {
    dh_x: Vec<u8>,
    hash: Hash,
}

pub struct SessionCreated {
    dh_y: Vec<u8>,
    hash: Hash,
    ts_b: u32,
}

pub struct SessionConfirmA {
    ri_a: RouterIdentity,
    ts_a: u32,
    sig: Signature,
}

pub struct SessionConfirmB {
    sig: Signature,
}

pub enum HandshakeFrame {
    SessionRequest(SessionRequest),
    SessionCreated(SessionCreated),
    SessionConfirmA(SessionConfirmA),
    SessionConfirmB(SessionConfirmB),
}

impl ResponseType for HandshakeFrame {
    type Item = ();
    type Error = ();
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HandshakeState {
    SessionRequest,
    SessionCreated,
    SessionConfirmA,
    SessionConfirmB,
    Established,
}

struct InboundHandshakeCodec {
    dh_key_builder: DHSessionKeyBuilder,
    dh_x: Vec<u8>,
    iv_enc: [u8; AES_BLOCK_SIZE],
    iv_dec: [u8; AES_BLOCK_SIZE],
    state: HandshakeState,
    aes: Option<Aes256>,
    decrypted: usize,
}

impl InboundHandshakeCodec {
    fn new(dh_key_builder: DHSessionKeyBuilder, iv_enc: [u8; AES_BLOCK_SIZE]) -> Self {
        let iv_dec = [0u8; AES_BLOCK_SIZE];
        InboundHandshakeCodec {
            dh_key_builder,
            dh_x: vec![],
            iv_enc,
            iv_dec,
            state: HandshakeState::SessionRequest,
            aes: None,
            decrypted: 0,
        }
    }
}

impl Decoder for InboundHandshakeCodec {
    type Item = HandshakeFrame;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> io::Result<Option<HandshakeFrame>> {
        let (consumed, f) = {
            // Parse frame for the current state
            let res = match self.state {
                HandshakeState::SessionRequest => frame::session_request(buf),
                HandshakeState::SessionConfirmA => {
                    match self.aes
                        .as_mut()
                        .unwrap()
                        .decrypt_blocks(&mut buf[self.decrypted..])
                    {
                        Some(end) => self.decrypted += end,
                        None => return Ok(None),
                    };
                    frame::session_confirm_a(&buf[0..self.decrypted])
                }
                _ => return Ok(None),
            };

            // Handle errors
            match res {
                IResult::Incomplete(_) => return Ok(None),
                IResult::Error(e) => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("parse error: {:?}", e),
                    ))
                }
                IResult::Done(i, frame) => (buf.offset(i), frame),
            }
        };

        // Save dh_x and iv_dec for later usage
        if let HandshakeFrame::SessionRequest(ref sr) = f {
            self.dh_x = sr.dh_x.clone();
            self.iv_dec.copy_from_slice(&sr.hash.0[AES_BLOCK_SIZE..]);
        }

        // Update the buffer
        buf.split_to(consumed);
        if self.state == HandshakeState::SessionConfirmA {
            self.decrypted -= consumed;
        }

        // Update the state machine
        self.state = match self.state {
            HandshakeState::SessionRequest => HandshakeState::SessionCreated,
            HandshakeState::SessionConfirmA => HandshakeState::SessionConfirmB,
            _ => panic!("Invalid inbound handshake state: {:?}", self.state),
        };

        Ok(Some(f))
    }
}

impl Encoder for InboundHandshakeCodec {
    type Item = HandshakeFrame;
    type Error = io::Error;

    fn encode(&mut self, frame: HandshakeFrame, buf: &mut BytesMut) -> io::Result<()> {
        let start = buf.len();
        buf.extend(repeat(0).take(NTCP_MTU));

        let res = match (self.state, frame) {
            (HandshakeState::SessionCreated, HandshakeFrame::SessionCreated(ref sc)) => {
                // Set up cryptor
                let session_key = self.dh_key_builder
                    .build_session_key(array_ref![self.dh_x, 0, 256]);
                self.aes = Some(Aes256::new(&session_key, &self.iv_enc, &self.iv_dec));
                // Serialise inner part of SessionCreated
                let mut tmp = [0u8; 48];
                match frame::gen_session_created_dec((&mut tmp, 0), &sc).map(|tup| tup.1) {
                    Ok(inner_sz) => {
                        // Encrypt message in-place
                        match self.aes.as_mut().unwrap().encrypt_blocks(&mut tmp) {
                            Some(end) if end == inner_sz => {
                                // Serialise outer SessionCreated
                                match frame::gen_session_created_enc((buf, start), &sc.dh_y, &tmp)
                                    .map(|tup| tup.1)
                                {
                                    Ok(sz) => {
                                        buf.truncate(sz);
                                        Ok(())
                                    }
                                    Err(e) => Err(e),
                                }
                            }
                            _ => {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "invalid serialization",
                                ));
                            }
                        }
                    }
                    Err(e) => Err(e),
                }
            }
            (HandshakeState::SessionConfirmB, HandshakeFrame::SessionConfirmB(ref scb)) => {
                match frame::gen_session_confirm_b((buf, start), &scb).map(|tup| tup.1) {
                    Ok(sz) => {
                        buf.truncate(sz);
                        // Encrypt message in-place
                        match self.aes.as_mut().unwrap().encrypt_blocks(&mut buf[start..]) {
                            Some(end) if start + end == sz => Ok(()),
                            _ => {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "invalid serialization",
                                ))
                            }
                        }
                    }
                    Err(e) => Err(e),
                }
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "incorrect state for sending",
                ))
            }
        };

        match res {
            Ok(()) => {
                // Update the state machine
                self.state = match self.state {
                    HandshakeState::SessionCreated => HandshakeState::SessionConfirmA,
                    HandshakeState::SessionConfirmB => HandshakeState::Established,
                    _ => panic!("Invalid inbound handshake state: {:?}", self.state),
                };
                Ok(())
            }
            Err(e) => match e {
                GenError::BufferTooSmall(sz) => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("message ({}) larger than MTU ({})", sz - start, NTCP_MTU),
                )),
                GenError::InvalidOffset
                | GenError::CustomError(_)
                | GenError::NotYetImplemented => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "could not generate",
                )),
            },
        }
    }
}

struct OutboundHandshakeCodec {
    dh_key_builder: DHSessionKeyBuilder,
    iv_enc: [u8; AES_BLOCK_SIZE],
    ri_remote: RouterIdentity,
    state: HandshakeState,
    aes: Option<Aes256>,
    decrypted: usize,
}

impl OutboundHandshakeCodec {
    fn new(
        dh_key_builder: DHSessionKeyBuilder,
        iv_enc: [u8; AES_BLOCK_SIZE],
        ri_remote: RouterIdentity,
    ) -> Self {
        OutboundHandshakeCodec {
            dh_key_builder,
            iv_enc,
            ri_remote,
            state: HandshakeState::SessionRequest,
            aes: None,
            decrypted: 0,
        }
    }
}

impl Decoder for OutboundHandshakeCodec {
    type Item = HandshakeFrame;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> io::Result<Option<HandshakeFrame>> {
        let (consumed, f) = {
            // Parse frame for the current state
            let res = match self.state {
                HandshakeState::SessionCreated => {
                    match frame::session_created_enc(&buf) {
                        IResult::Incomplete(_) => return Ok(None),
                        IResult::Error(e) => {
                            return Err(io::Error::new(
                                io::ErrorKind::Other,
                                format!("parse error: {:?}", e),
                            ))
                        }
                        IResult::Done(i, mut sce) => {
                            // Set up cryptor
                            let session_key = self.dh_key_builder
                                .build_session_key(array_ref![sce.0, 0, 256]);
                            self.aes = Some(Aes256::new(
                                &session_key,
                                &self.iv_enc,
                                array_ref![sce.0, sce.0.len() - AES_BLOCK_SIZE, AES_BLOCK_SIZE],
                            ));
                            // Decrypt remainder of SessionCreated message
                            match self.aes.as_mut().unwrap().decrypt_blocks(&mut sce.1) {
                                Some(end) if end == sce.1.len() => {
                                    match frame::session_created_dec(&sce.1) {
                                        IResult::Incomplete(_) => {
                                            return Err(io::Error::new(
                                                io::ErrorKind::Other,
                                                format!("incomplete parse error"),
                                            ))
                                        }
                                        IResult::Error(e) => {
                                            return Err(io::Error::new(
                                                io::ErrorKind::Other,
                                                format!("parse error: {:?}", e),
                                            ))
                                        }
                                        IResult::Done(_, scd) => IResult::Done(
                                            i,
                                            HandshakeFrame::SessionCreated(SessionCreated {
                                                dh_y: sce.0,
                                                hash: scd.0,
                                                ts_b: scd.1,
                                            }),
                                        ),
                                    }
                                }
                                Some(sz) => {
                                    return Err(io::Error::new(
                                        io::ErrorKind::Other,
                                        format!(
                                            "incomplete encrypt error, encrypted {} out of {}",
                                            sz,
                                            sce.1.len()
                                        ),
                                    ))
                                }
                                None => return Ok(None),
                            }
                        }
                    }
                }
                HandshakeState::SessionConfirmB => {
                    match self.aes
                        .as_mut()
                        .unwrap()
                        .decrypt_blocks(&mut buf[self.decrypted..])
                    {
                        Some(end) => self.decrypted += end,
                        None => return Ok(None),
                    };
                    frame::session_confirm_b(&buf[0..self.decrypted], &self.ri_remote)
                }
                _ => return Ok(None),
            };

            // Handle parser result
            match res {
                IResult::Incomplete(_) => return Ok(None),
                IResult::Error(e) => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("parse error: {:?}", e),
                    ))
                }
                IResult::Done(i, frame) => (buf.offset(i), frame),
            }
        };

        // Update the buffer
        buf.split_to(consumed);
        if self.state == HandshakeState::SessionConfirmB {
            self.decrypted -= consumed;
        }

        // Update the state machine
        self.state = match self.state {
            HandshakeState::SessionCreated => HandshakeState::SessionConfirmA,
            HandshakeState::SessionConfirmB => HandshakeState::Established,
            _ => panic!("Invalid outbound handshake state: {:?}", self.state),
        };

        Ok(Some(f))
    }
}

impl Encoder for OutboundHandshakeCodec {
    type Item = HandshakeFrame;
    type Error = io::Error;

    fn encode(&mut self, frame: HandshakeFrame, buf: &mut BytesMut) -> io::Result<()> {
        let start = buf.len();
        buf.extend(repeat(0).take(NTCP_MTU));

        let res = match (self.state, frame) {
            (HandshakeState::SessionRequest, HandshakeFrame::SessionRequest(ref sr)) => {
                match frame::gen_session_request((buf, start), &sr).map(|tup| tup.1) {
                    Ok(sz) => {
                        buf.truncate(sz);
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
            (HandshakeState::SessionConfirmA, HandshakeFrame::SessionConfirmA(ref sca)) => {
                match frame::gen_session_confirm_a((buf, start), &sca).map(|tup| tup.1) {
                    Ok(sz) => {
                        buf.truncate(sz);
                        // Encrypt message in-place
                        match self.aes.as_mut().unwrap().encrypt_blocks(&mut buf[start..]) {
                            Some(end) if start + end == sz => Ok(()),
                            _ => {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "invalid serialization",
                                ))
                            }
                        }
                    }
                    Err(e) => Err(e),
                }
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "incorrect state for sending",
                ))
            }
        };

        match res {
            Ok(()) => {
                // Update the state machine
                self.state = match self.state {
                    HandshakeState::SessionRequest => HandshakeState::SessionCreated,
                    HandshakeState::SessionConfirmA => HandshakeState::SessionConfirmB,
                    _ => panic!("Invalid outbound handshake state: {:?}", self.state),
                };
                Ok(())
            }
            Err(e) => match e {
                GenError::BufferTooSmall(sz) => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("message ({}) larger than MTU ({})", sz - start, NTCP_MTU),
                )),
                GenError::InvalidOffset
                | GenError::CustomError(_)
                | GenError::NotYetImplemented => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "could not generate",
                )),
            },
        }
    }
}

//
// Message transport
//

pub enum Frame {
    Standard(Message),
    TimeSync(u32),
}

impl ResponseType for Message {
    type Item = ();
    type Error = ();
}

impl ResponseType for Frame {
    type Item = ();
    type Error = ();
}

use std::fmt;

impl fmt::Debug for Frame {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Frame::Standard(_) => "Standard message".fmt(formatter),
            &Frame::TimeSync(ts) => format!("Timesync ({})", ts).fmt(formatter),
        }
    }
}

pub struct Codec {
    aes: Aes256,
    decrypted: usize,
}

impl From<InboundHandshakeCodec> for Codec {
    fn from(established: InboundHandshakeCodec) -> Self {
        Codec {
            aes: established.aes.unwrap(),
            decrypted: established.decrypted,
        }
    }
}

impl From<OutboundHandshakeCodec> for Codec {
    fn from(established: OutboundHandshakeCodec) -> Self {
        Codec {
            aes: established.aes.unwrap(),
            decrypted: established.decrypted,
        }
    }
}

impl Decoder for Codec {
    type Item = Frame;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> io::Result<Option<Frame>> {
        // Encrypt message in-place
        match self.aes.decrypt_blocks(&mut buf[self.decrypted..]) {
            Some(end) => self.decrypted += end,
            None => return Ok(None),
        };

        // Parse a frame
        let (consumed, f) = match frame::frame(&buf[0..self.decrypted]) {
            IResult::Incomplete(_) => return Ok(None),
            IResult::Error(e) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("parse error: {:?}", e),
                ))
            }
            IResult::Done(i, frame) => (buf.offset(i), frame),
        };

        buf.split_to(consumed);
        self.decrypted -= consumed;

        Ok(Some(f))
    }
}

impl Encoder for Codec {
    type Item = Frame;
    type Error = io::Error;

    fn encode(&mut self, frame: Frame, buf: &mut BytesMut) -> io::Result<()> {
        let start = buf.len();
        buf.extend(repeat(0).take(NTCP_MTU));

        match frame::gen_frame((buf, start), &frame).map(|tup| tup.1) {
            Ok(sz) => {
                buf.truncate(sz);
                // Encrypt message in-place
                match self.aes.encrypt_blocks(&mut buf[start..]) {
                    Some(end) if start + end == sz => Ok(()),
                    _ => Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid serialization",
                    )),
                }
            }
            Err(e) => match e {
                GenError::BufferTooSmall(sz) => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("message ({}) larger than MTU ({})", sz - start, NTCP_MTU),
                )),
                GenError::InvalidOffset
                | GenError::CustomError(_)
                | GenError::NotYetImplemented => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "could not generate",
                )),
            },
        }
    }
}

//
// Common parts of the handshake protocols
//

fn gen_session_confirm_sig_msg(state: &SharedHandshakeState, own_ri: bool) -> Vec<u8> {
    let ri = if own_ri {
        &state.own_ri
    } else {
        &state.ri_remote.as_ref().unwrap()
    };
    let base_len = 907; // 2*256 + 387 + 2*4
    let mut buf = Vec::with_capacity(base_len);
    buf.extend(repeat(0).take(base_len));
    loop {
        match frame::gen_session_confirm_sig_msg(
            (&mut buf[..], 0),
            &state.dh_x,
            &state.dh_y,
            ri,
            state.ts_a,
            state.ts_b,
        ).map(|tup| tup.1)
        {
            Ok(sz) => {
                buf.truncate(sz);
                break;
            }
            Err(e) => match e {
                GenError::BufferTooSmall(sz) => {
                    buf.extend(repeat(0).take(sz - base_len));
                }
                _ => panic!("Couldn't serialize Signature message (Own RI? {})"),
            },
        }
    }
    buf
}

struct SharedHandshakeState {
    own_ri: RouterIdentity,
    own_key: SigningPrivateKey,
    ri_remote: Option<RouterIdentity>,
    dh_x: Vec<u8>,
    dh_y: Vec<u8>,
    ts_a: u32,
    ts_b: u32,
}

// Placeholder for internal state when connection is established
struct Established;

trait HandshakeStateTrait {
    fn next_frame(self) -> (Option<HandshakeFrame>, Self);
    fn handle_frame(self, frame: HandshakeFrame) -> (Result<(), io::Error>, Self);
    fn is_established(&self) -> bool;
}

//
// Inbound handshake protocol
//

struct IBHandshake<S> {
    shared: SharedHandshakeState,
    state: S,
}

// First, the state transformations

// - Message 1: <-- SessionRequest

struct IBSessionRequest;

impl IBHandshake<IBSessionRequest> {
    fn new(own_ri: RouterIdentity, own_key: SigningPrivateKey, dh_y: Vec<u8>) -> Self {
        IBHandshake {
            shared: SharedHandshakeState {
                own_ri,
                own_key,
                ri_remote: None,
                dh_x: vec![],
                dh_y,
                ts_a: 0,
                ts_b: 0,
            },
            state: IBSessionRequest,
        }
    }

    fn next(self, hxy: Hash) -> IBHandshake<OBSessionCreated> {
        IBHandshake {
            shared: self.shared,
            state: OBSessionCreated { hxy },
        }
    }
}

// - Message 2: --> SessionCreated

struct OBSessionCreated {
    hxy: Hash,
}

impl IBHandshake<OBSessionCreated> {
    fn next(self) -> (SessionCreated, IBHandshake<IBSessionConfirmA>) {
        (
            SessionCreated {
                dh_y: self.shared.dh_y.clone(),
                hash: self.state.hxy,
                ts_b: self.shared.ts_b,
            },
            IBHandshake {
                shared: self.shared,
                state: IBSessionConfirmA {
                    rtt_timer: SystemTime::now(),
                },
            },
        )
    }
}

// - Message 3: <-- SessionConfirmA

struct IBSessionConfirmA {
    rtt_timer: SystemTime,
}

impl IBHandshake<IBSessionConfirmA> {
    fn next(self, sig: Signature) -> IBHandshake<OBSessionConfirmB> {
        IBHandshake {
            shared: self.shared,
            state: OBSessionConfirmB { sig },
        }
    }
}

// - Message 4: --> SessionConfirmB

struct OBSessionConfirmB {
    sig: Signature,
}

impl IBHandshake<OBSessionConfirmB> {
    fn next(self) -> (SessionConfirmB, IBHandshake<Established>) {
        (
            SessionConfirmB {
                sig: self.state.sig,
            },
            IBHandshake {
                shared: self.shared,
                state: Established,
            },
        )
    }
}

// Next, the state transitions

enum IBHandshakeState {
    SessionRequest(IBHandshake<IBSessionRequest>),
    SessionCreated(IBHandshake<OBSessionCreated>),
    SessionConfirmA(IBHandshake<IBSessionConfirmA>),
    SessionConfirmB(IBHandshake<OBSessionConfirmB>),
    Established(IBHandshake<Established>),
}

impl HandshakeStateTrait for IBHandshakeState {
    fn next_frame(self) -> (Option<HandshakeFrame>, Self) {
        match self {
            IBHandshakeState::SessionCreated(state) => {
                // Part 2
                debug!("Sending SessionCreated");
                let (sc, sca_state) = state.next();
                (
                    Some(HandshakeFrame::SessionCreated(sc)),
                    IBHandshakeState::SessionConfirmA(sca_state),
                )
            }
            IBHandshakeState::SessionConfirmB(state) => {
                // Part 4
                debug!("Sending SessionConfirmB");
                let (scb, e_state) = state.next();
                (
                    Some(HandshakeFrame::SessionConfirmB(scb)),
                    IBHandshakeState::Established(e_state),
                )
            }
            state => (None, state),
        }
    }

    fn handle_frame(self, frame: HandshakeFrame) -> (Result<(), io::Error>, Self) {
        match (self, frame) {
            (IBHandshakeState::SessionRequest(mut state), HandshakeFrame::SessionRequest(sr)) => {
                // Part 1
                debug!("Received SessionRequest");
                // Check that Alice knows who she is trying to talk with, and
                // that the X isn't corrupt
                let mut hxxorhb = Hash::digest(&sr.dh_x[..]);
                hxxorhb.xor(&state.shared.own_ri.hash());
                if hxxorhb != sr.hash {
                    return (
                        Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Invalid SessionRequest HXxorHB",
                        )),
                        IBHandshakeState::SessionRequest(state),
                    );
                }
                // TODO check replays
                let now = SystemTime::now();
                let mut ts_b = now.duration_since(UNIX_EPOCH).expect("Time went backwards");
                ts_b.add_assign(Duration::from_millis(500));
                // Update local state
                state.shared.dh_x = sr.dh_x;
                state.shared.ts_b = ts_b.as_secs() as u32;
                let mut xy = Vec::from(&state.shared.dh_x[..]);
                xy.extend_from_slice(&state.shared.dh_y);
                let hxy = Hash::digest(&xy);
                (Ok(()), IBHandshakeState::SessionCreated(state.next(hxy)))
            }
            (
                IBHandshakeState::SessionConfirmA(mut state),
                HandshakeFrame::SessionConfirmA(sca),
            ) => {
                // Part 3
                debug!("Received SessionConfirmA");
                // Get peer skew
                let rtt = state
                    .state
                    .rtt_timer
                    .elapsed()
                    .expect("Time went backwards?");
                debug!("Peer RTT: {:?}", rtt);
                // Update local state
                state.shared.ri_remote = Some(sca.ri_a);
                state.shared.ts_a = sca.ts_a;
                // Generate message to be verified
                let msg = gen_session_confirm_sig_msg(&state.shared, true);
                if !state
                    .shared
                    .ri_remote
                    .as_ref()
                    .unwrap()
                    .signing_key
                    .verify(&msg, &sca.sig)
                {
                    return (
                        Err(io::Error::new(
                            io::ErrorKind::ConnectionRefused,
                            "Invalid SessionConfirmA signature",
                        )),
                        IBHandshakeState::SessionConfirmA(state),
                    );
                }
                // Generate message to be signed
                let msg = gen_session_confirm_sig_msg(&state.shared, false);
                let sig = state.shared.own_key.sign(&msg);
                (Ok(()), IBHandshakeState::SessionConfirmB(state.next(sig)))
            }
            (state, _) => (
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Unexpected handshake frame",
                )),
                state,
            ),
        }
    }

    fn is_established(&self) -> bool {
        match self {
            &IBHandshakeState::Established(_) => true,
            _ => false,
        }
    }
}

//
// Outbound handshake protocol
//

struct OBHandshake<S> {
    shared: SharedHandshakeState,
    state: S,
}

// First, the state transformations

// - Message 1: --> SessionRequest

struct OBSessionRequest {
    hxxorhb: Hash,
}

impl OBHandshake<OBSessionRequest> {
    fn new(
        own_ri: RouterIdentity,
        own_key: SigningPrivateKey,
        ri_remote: RouterIdentity,
        dh_x: Vec<u8>,
        hxxorhb: Hash,
    ) -> Self {
        OBHandshake {
            shared: SharedHandshakeState {
                own_ri,
                own_key,
                ri_remote: Some(ri_remote),
                dh_x,
                dh_y: vec![],
                ts_a: 0,
                ts_b: 0,
            },
            state: OBSessionRequest { hxxorhb },
        }
    }

    fn next(self) -> (SessionRequest, OBHandshake<IBSessionCreated>) {
        (
            SessionRequest {
                dh_x: self.shared.dh_x.clone(),
                hash: self.state.hxxorhb,
            },
            OBHandshake {
                shared: self.shared,
                state: IBSessionCreated {
                    rtt_timer: SystemTime::now(),
                },
            },
        )
    }
}

// - Message 2: <-- SessionCreated

struct IBSessionCreated {
    rtt_timer: SystemTime,
}

impl OBHandshake<IBSessionCreated> {
    fn next(self, sig: Signature) -> OBHandshake<OBSessionConfirmA> {
        OBHandshake {
            shared: self.shared,
            state: OBSessionConfirmA { sig },
        }
    }
}

// - Message 3: --> SessionConfirmA

struct OBSessionConfirmA {
    sig: Signature,
}

impl OBHandshake<OBSessionConfirmA> {
    fn next(self) -> (SessionConfirmA, OBHandshake<IBSessionConfirmB>) {
        (
            SessionConfirmA {
                ri_a: self.shared.own_ri.clone(),
                ts_a: self.shared.ts_a,
                sig: self.state.sig,
            },
            OBHandshake {
                shared: self.shared,
                state: IBSessionConfirmB,
            },
        )
    }
}

// - Message 4: <-- SessionConfirmB

struct IBSessionConfirmB;

impl OBHandshake<IBSessionConfirmB> {
    fn next(self) -> OBHandshake<Established> {
        OBHandshake {
            shared: self.shared,
            state: Established,
        }
    }
}

// Next, the state transitions

enum OBHandshakeState {
    SessionRequest(OBHandshake<OBSessionRequest>),
    SessionCreated(OBHandshake<IBSessionCreated>),
    SessionConfirmA(OBHandshake<OBSessionConfirmA>),
    SessionConfirmB(OBHandshake<IBSessionConfirmB>),
    Established(OBHandshake<Established>),
}

impl HandshakeStateTrait for OBHandshakeState {
    fn next_frame(self) -> (Option<HandshakeFrame>, Self) {
        match self {
            OBHandshakeState::SessionRequest(state) => {
                // Part 1
                debug!("Sending SessionRequest");
                let (sr, sc_state) = state.next();
                (
                    Some(HandshakeFrame::SessionRequest(sr)),
                    OBHandshakeState::SessionCreated(sc_state),
                )
            }
            OBHandshakeState::SessionConfirmA(state) => {
                // Part 3
                debug!("Sending SessionConfirmA");
                let (sca, scb_state) = state.next();
                (
                    Some(HandshakeFrame::SessionConfirmA(sca)),
                    OBHandshakeState::SessionConfirmB(scb_state),
                )
            }
            state => (None, state),
        }
    }

    fn handle_frame(self, frame: HandshakeFrame) -> (Result<(), io::Error>, Self) {
        match (self, frame) {
            (OBHandshakeState::SessionCreated(mut state), HandshakeFrame::SessionCreated(sc)) => {
                // Part 2
                debug!("Received SessionCreated");
                // Get peer skew
                let rtt = state
                    .state
                    .rtt_timer
                    .elapsed()
                    .expect("Time went backwards?");
                debug!("Peer RTT: {:?}", rtt);
                let now = SystemTime::now();
                let mut ts_a = now.duration_since(UNIX_EPOCH).expect("Time went backwards");
                ts_a.add_assign(Duration::from_millis(500));
                // Update local state
                state.shared.dh_y = sc.dh_y;
                state.shared.ts_a = ts_a.as_secs() as u32;
                state.shared.ts_b = sc.ts_b;
                // Generate message to be signed
                let msg = gen_session_confirm_sig_msg(&state.shared, false);
                // Check part 2 (which happens to be hash of first part of signed message)
                let hxy = Hash::digest(&msg[..512]);
                if hxy != sc.hash {
                    return (
                        Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Invalid SessionCreated hash",
                        )),
                        OBHandshakeState::SessionCreated(state),
                    );
                }
                let sig = state.shared.own_key.sign(&msg);
                (Ok(()), OBHandshakeState::SessionConfirmA(state.next(sig)))
            }
            (OBHandshakeState::SessionConfirmB(state), HandshakeFrame::SessionConfirmB(scb)) => {
                // Part 4
                debug!("Received SessionConfirmB");
                // Generate message to be verified
                let msg = gen_session_confirm_sig_msg(&state.shared, true);
                if !state
                    .shared
                    .ri_remote
                    .as_ref()
                    .unwrap()
                    .signing_key
                    .verify(&msg, &scb.sig)
                {
                    return (
                        Err(io::Error::new(
                            io::ErrorKind::ConnectionRefused,
                            "Invalid SessionConfirmB signature",
                        )),
                        OBHandshakeState::SessionConfirmB(state),
                    );
                }
                (Ok(()), OBHandshakeState::Established(state.next()))
            }
            (state, _) => (
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Unexpected handshake frame",
                )),
                state,
            ),
        }
    }

    fn is_established(&self) -> bool {
        match self {
            &OBHandshakeState::Established(_) => true,
            _ => false,
        }
    }
}

//
// Actor to execute the handshake protocols
//

struct Handshake<C, S> {
    state: Option<S>,
    phantom: PhantomData<C>,
}

impl<C, S> Actor for Handshake<C, S>
where
    C: Decoder<Item = HandshakeFrame, Error = io::Error>,
    C: Encoder<Item = HandshakeFrame, Error = io::Error>,
    C: 'static,
    Codec: From<C>,
    S: HandshakeStateTrait + 'static,
{
    type Context = FramedContext<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        info!("Starting handshake");

        match self.state.take().unwrap().next_frame() {
            (Some(frame), state) => {
                self.state = Some(state);
                let _ = ctx.send(frame);
            }
            (None, state) => {
                self.state = Some(state);
            }
        }
    }
}

impl<C, S> FramedActor for Handshake<C, S>
where
    C: Decoder<Item = HandshakeFrame, Error = io::Error>,
    C: Encoder<Item = HandshakeFrame, Error = io::Error>,
    C: 'static,
    Codec: From<C>,
    S: HandshakeStateTrait + 'static,
{
    type Io = TcpStream;
    type Codec = C;

    /// This is main event loop for the NTCP handshake
    fn handle(&mut self, msg: io::Result<HandshakeFrame>, ctx: &mut Self::Context) {
        match msg {
            Ok(frame) => {
                match self.state.take().unwrap().handle_frame(frame) {
                    (Ok(()), state) => match state.next_frame() {
                        (Some(frame), state) => {
                            self.state = Some(state);
                            let _ = ctx.send(frame);
                        }
                        (None, state) => {
                            self.state = Some(state);
                        }
                    },
                    (Err(e), state) => {
                        self.state = Some(state);
                        error!("Error while handling handshake frame: {}", e);
                        ctx.stop();
                    }
                };

                // If we are established, fire off a real session
                if self.state.as_ref().map_or(false, |s| s.is_established()) {
                    // Schedule transmutation of the Framed
                    ctx.run_later(Duration::from_millis(100), |_, ctx| {
                        info!("Finished handshake!");
                        // Now transmute the Framed from a handshake into a session
                        let handshake_framed = ctx.take().unwrap();
                        let (parts, handshake_codec) = handshake_framed.into_parts_and_codec();

                        // Start the Session actor
                        let session: Address<_> = Session::create_from_framed(
                            Framed::from_parts(parts, Codec::from(handshake_codec)),
                            |_| Session,
                        );
                        // TODO: Store the session
                    });

                    // Ensure all handshake messages are sent before transmuting the
                    // Framed, otherwise the IVs can get out of sync.
                    // drain() blocks all other events until the specified future
                    // completes, so the scheduled call will be run afterwards.
                    debug!("Waiting for handshake to finish...");
                    let _ = ctx.drain();
                }
            }
            Err(err) => {
                /// We'll stop NTCP handshake actor on any error, high likely it is just
                /// termination of the TCP stream.
                error!("Error while performing handshake: {}", err);
                ctx.stop()
            }
        }
    }
}

//
// Actor responsible for communication with a particular NTCP peer
//

struct Session;

impl Actor for Session {
    type Context = FramedContext<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        info!("Connection established!");

        // TODO: Send useful initial messages
        let _ = ctx.send(Frame::Standard(Message::dummy_data()));
        let _ = ctx.send(Frame::TimeSync(42));
        let _ = ctx.send(Frame::Standard(Message::dummy_data()));
    }
}

impl FramedActor for Session {
    type Io = TcpStream;
    type Codec = Codec;

    /// This is main inbound event loop for the NTCP session
    fn handle(&mut self, msg: io::Result<Frame>, ctx: &mut Self::Context) {
        match msg {
            Ok(frame) => debug!("Received frame: {:?}", frame),
            Err(err) => {
                error!("Error while connected: {}", err);
                ctx.stop()
            }
        }
    }
}

impl Handler<Message> for Session {
    type Result = MessageResult<Message>;

    /// This is main outbound event loop for the NTCP session
    fn handle(&mut self, msg: Message, ctx: &mut Self::Context) -> Self::Result {
        let _ = ctx.send(Frame::Standard(msg));
        Ok(())
    }
}

//
// Connection management engine
//

pub struct Engine {
    own_ri: RouterIdentity,
    own_key: SigningPrivateKey,
}

impl Actor for Engine {
    type Context = Context<Self>;
}

impl StreamHandler<io::Result<TcpConnect>> for Engine {}

impl Handler<io::Result<TcpConnect>> for Engine {
    type Result = MessageResult<TcpConnect>;

    fn handle(&mut self, msg: io::Result<TcpConnect>, ctx: &mut Self::Context) -> Self::Result {
        match msg {
            Ok(socket) => self.accept(socket),
            Err(err) => {
                error!("Error during accept: {}", err);
                ctx.stop()
            }
        }

        Ok(())
    }
}

impl Engine {
    pub fn new(own_ri: RouterIdentity, own_key: SigningPrivateKey) -> Self {
        Engine { own_ri, own_key }
    }

    fn accept(&self, socket: TcpConnect) {
        info!("Incoming socket!");

        // Generate a new DH pair
        let dh_key_builder = DHSessionKeyBuilder::new();
        let dh_y = dh_key_builder.get_pub();
        let mut iv_enc = [0u8; AES_BLOCK_SIZE];
        iv_enc.copy_from_slice(&dh_y[dh_y.len() - AES_BLOCK_SIZE..]);

        // TODO: Find a way to refer to the codec from here, to deduplicate state
        let codec = InboundHandshakeCodec::new(dh_key_builder, iv_enc);
        let state = IBHandshakeState::SessionRequest(IBHandshake::new(
            self.own_ri.clone(),
            self.own_key.clone(),
            dh_y,
        ));

        // For each incoming connection we create `InboundHandshake` actor
        // to conduct the NTCP handshake
        // let server = self.chat.clone();
        let _: () = Handshake {
            state: Some(state),
            phantom: PhantomData,
        }.framed(socket.0, codec);
    }

    pub fn connect(&self, peer_ri: RouterIdentity, addr: &SocketAddr) {
        let own_ri = self.own_ri.clone();
        let own_key = self.own_key.clone();
        let handle = Arbiter::handle();

        // Connect to the peer
        // Return a transport ready for sending and receiving Frames
        // The layer above will convert I2NP packets to Frames
        // (or should the Engine handle timesync packets itself?)
        let transport = TcpStream::connect(&addr, &handle).and_then(|socket| {
            // Generate a new DH pair
            let dh_key_builder = DHSessionKeyBuilder::new();
            let dh_x = dh_key_builder.get_pub();
            let mut hxxorhb = Hash::digest(&dh_x[..]);
            hxxorhb.xor(&peer_ri.hash());
            let mut iv_enc = [0u8; AES_BLOCK_SIZE];
            iv_enc.copy_from_slice(&hxxorhb.0[AES_BLOCK_SIZE..]);

            // TODO: Find a way to refer to the codec from here, to deduplicate state
            let codec = OutboundHandshakeCodec::new(dh_key_builder, iv_enc, peer_ri.clone());
            let state = OBHandshakeState::SessionRequest(OBHandshake::new(
                own_ri,
                own_key,
                peer_ri,
                dh_x,
                hxxorhb,
            ));

            let _: () = Handshake {
                state: Some(state),
                phantom: PhantomData,
            }.framed(socket, codec);

            future::ok(())
        });

        // Add a timeout
        let timeout = Timeout::new(Duration::new(10, 0), &handle).unwrap();
        handle.spawn(
            transport
                .map(Ok)
                .select(timeout.map(Err))
                .then(|res| {
                    match res {
                        // The handshake finished before the timeout fired
                        Ok((Ok(()), _timeout)) => future::ok(()),

                        // The timeout fired before the handshake finished
                        Ok((Err(()), _handshake)) => future::err(io::Error::new(
                            io::ErrorKind::Other,
                            "timeout during handshake",
                        )),

                        // One of the futures (handshake or timeout) hit an error
                        Err((e, _other)) => future::err(e),
                    }
                })
                .map_err(|e| {
                    error!("Could not connect to server: {}", e);
                    process::exit(1)
                }),
        )
    }
}
