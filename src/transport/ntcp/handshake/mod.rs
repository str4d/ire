use bytes::BytesMut;
use cookie_factory::GenError;
use futures::{future, Async, Future, Poll, Sink, StartSend, Stream};
use nom::{Err, Offset};
use std::io;
use std::iter::repeat;
use std::ops::AddAssign;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio_codec::{Decoder, Encoder, Framed, FramedParts};
use tokio_io::{AsyncRead, AsyncWrite, IoFuture};

use super::{Codec, NTCP_MTU};
use crypto::{Aes256, Signature, SigningPrivateKey, AES_BLOCK_SIZE};
use data::{Hash, RouterIdentity};
use transport::DHSessionKeyBuilder;

mod frame;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HandshakeState {
    SessionRequest,
    SessionCreated,
    SessionConfirmA,
    SessionConfirmB,
    Established,
}

pub struct InboundHandshakeCodec {
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

impl From<InboundHandshakeCodec> for Codec {
    fn from(established: InboundHandshakeCodec) -> Self {
        Codec {
            aes: established.aes.unwrap(),
            decrypted: established.decrypted,
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
                    match self
                        .aes
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
                Err(Err::Incomplete(_)) => return Ok(None),
                Err(Err::Error(e)) | Err(Err::Failure(e)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("parse error: {:?}", e),
                    ))
                }
                Ok((i, frame)) => (buf.offset(i), frame),
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
                let session_key = self
                    .dh_key_builder
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

pub struct OutboundHandshakeCodec {
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

impl From<OutboundHandshakeCodec> for Codec {
    fn from(established: OutboundHandshakeCodec) -> Self {
        Codec {
            aes: established.aes.unwrap(),
            decrypted: established.decrypted,
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
                        Err(Err::Incomplete(_)) => return Ok(None),
                        Err(Err::Error(e)) | Err(Err::Failure(e)) => {
                            return Err(io::Error::new(
                                io::ErrorKind::Other,
                                format!("parse error: {:?}", e),
                            ))
                        }
                        Ok((i, mut sce)) => {
                            // Set up cryptor
                            let session_key = self
                                .dh_key_builder
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
                                        Err(Err::Incomplete(_)) => {
                                            return Err(io::Error::new(
                                                io::ErrorKind::Other,
                                                format!("incomplete parse error"),
                                            ))
                                        }
                                        Err(Err::Error(e)) | Err(Err::Failure(e)) => {
                                            return Err(io::Error::new(
                                                io::ErrorKind::Other,
                                                format!("parse error: {:?}", e),
                                            ))
                                        }
                                        Ok((_, scd)) => Ok((
                                            i,
                                            HandshakeFrame::SessionCreated(SessionCreated {
                                                dh_y: sce.0,
                                                hash: scd.0,
                                                ts_b: scd.1,
                                            }),
                                        )),
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
                    match self
                        .aes
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
                Err(Err::Incomplete(_)) => return Ok(None),
                Err(Err::Error(e)) | Err(Err::Failure(e)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("parse error: {:?}", e),
                    ))
                }
                Ok((i, frame)) => (buf.offset(i), frame),
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
pub struct Established;

pub trait HandshakeStateTrait {
    fn next_frame(self) -> (Option<HandshakeFrame>, Self);
    fn handle_frame(self, frame: HandshakeFrame) -> (Result<(), io::Error>, Self);
    fn is_established(&self) -> bool;
}

//
// Inbound handshake protocol
//

pub struct IBHandshake<S> {
    shared: SharedHandshakeState,
    state: S,
}

// First, the state transformations

// - Message 1: <-- SessionRequest

pub struct IBSessionRequest;

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

pub struct OBSessionCreated {
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

pub struct IBSessionConfirmA {
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

pub struct OBSessionConfirmB {
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

pub enum IBHandshakeState {
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
                if let Err(e) = state
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

pub struct OBHandshake<S> {
    shared: SharedHandshakeState,
    state: S,
}

// First, the state transformations

// - Message 1: --> SessionRequest

pub struct OBSessionRequest {
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

pub struct IBSessionCreated {
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

pub struct OBSessionConfirmA {
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

pub struct IBSessionConfirmB;

impl OBHandshake<IBSessionConfirmB> {
    fn next(self) -> OBHandshake<Established> {
        OBHandshake {
            shared: self.shared,
            state: Established,
        }
    }
}

// Next, the state transitions

pub enum OBHandshakeState {
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
                if let Err(e) = state
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
// Transport to execute the handshake protocols
//

pub struct HandshakeTransport<T, C, S> {
    upstream: Framed<T, C>,
    state: Option<S>,
}

impl<T, C, S> HandshakeTransport<T, C, S>
where
    T: AsyncRead + AsyncWrite,
    T: Send + 'static,
    C: Decoder<Item = HandshakeFrame, Error = io::Error>,
    C: Encoder<Item = HandshakeFrame, Error = io::Error>,
    S: HandshakeStateTrait,
{
    /// Returns a future of a stream of `Framed<T, Codec>`s that are connected
    pub fn listen(
        stream: T,
        own_ri: RouterIdentity,
        own_key: SigningPrivateKey,
    ) -> IoFuture<Framed<T, Codec>> {
        // Generate a new DH pair
        let dh_key_builder = DHSessionKeyBuilder::new();
        let dh_y = dh_key_builder.get_pub();
        let mut iv_enc = [0u8; AES_BLOCK_SIZE];
        iv_enc.copy_from_slice(&dh_y[dh_y.len() - AES_BLOCK_SIZE..]);

        // TODO: Find a way to refer to the codec from here, to deduplicate state
        let codec = InboundHandshakeCodec::new(dh_key_builder, iv_enc);
        let mut t = HandshakeTransport {
            upstream: codec.framed(stream),
            state: Some(IBHandshakeState::SessionRequest(IBHandshake::new(
                own_ri, own_key, dh_y,
            ))),
        };

        if let Err(e) = t.send_and_handle_frames() {
            let err = format!("Failed to handle frames: {:?}", e);
            return Box::new(future::err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                err,
            )));
        }

        let mut connector = TransportConnector { transport: Some(t) };

        if let Err(e) = connector.poll() {
            let err = format!("Failed to handle frames: {:?}", e);
            return Box::new(future::err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                err,
            )));
        }

        Box::new(connector)
    }

    /// Returns a future of an `Framed<T, Codec>` that is connected
    pub fn connect(
        stream: T,
        own_ri: RouterIdentity,
        own_key: SigningPrivateKey,
        ri_remote: RouterIdentity,
    ) -> IoFuture<Framed<T, Codec>> {
        // Generate a new DH pair
        let dh_key_builder = DHSessionKeyBuilder::new();
        let dh_x = dh_key_builder.get_pub();
        let mut hxxorhb = Hash::digest(&dh_x[..]);
        hxxorhb.xor(&ri_remote.hash());
        let mut iv_enc = [0u8; AES_BLOCK_SIZE];
        iv_enc.copy_from_slice(&hxxorhb.0[AES_BLOCK_SIZE..]);

        // TODO: Find a way to refer to the codec from here, to deduplicate state
        let codec = OutboundHandshakeCodec::new(dh_key_builder, iv_enc, ri_remote.clone());
        let mut t = HandshakeTransport {
            upstream: codec.framed(stream),
            state: Some(OBHandshakeState::SessionRequest(OBHandshake::new(
                own_ri, own_key, ri_remote, dh_x, hxxorhb,
            ))),
        };

        if let Err(e) = t.send_and_handle_frames() {
            let err = format!("Failed to handle frames: {:?}", e);
            return Box::new(future::err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                err,
            )));
        }

        let mut connector = TransportConnector { transport: Some(t) };

        if let Err(e) = connector.poll() {
            let err = format!("Failed to handle frames: {:?}", e);
            return Box::new(future::err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                err,
            )));
        }

        Box::new(connector)
    }

    fn next_frame(&mut self) -> Option<HandshakeFrame> {
        let state = self.state.take().unwrap();
        let (frame, new_state) = state.next_frame();
        self.state = Some(new_state);
        frame
    }

    fn handle_frame(&mut self, frame: HandshakeFrame) -> Result<(), io::Error> {
        let state = self.state.take().unwrap();
        let (res, new_state) = state.handle_frame(frame);
        self.state = Some(new_state);
        res
    }

    // Note that this can only return one of
    // - Error
    // - Async::NotReady
    // - Async::Ready(None)
    // All other results are handled until one of these three is reached.
    fn send_and_handle_frames(&mut self) -> Poll<Option<()>, io::Error> {
        self.send_frames()?;
        self.handle_frames()
    }

    fn send_frames(&mut self) -> Result<(), io::Error> {
        //FIXME: find a way to use a future here
        while let Some(f) = self.next_frame() {
            if let Err(e) = self.send_frame(f) {
                return Err(e);
            }
        }
        Ok(())
    }

    fn send_frame(&mut self, frame: HandshakeFrame) -> Poll<(), io::Error> {
        self.start_send(frame).and_then(|_| self.poll_complete())
    }

    fn handle_frames(&mut self) -> Poll<Option<()>, io::Error> {
        loop {
            // try_ready will return if we hit an error or NotReady.
            if try_ready!(self.poll()).is_none() {
                return Ok(Async::Ready(None));
            }
        }
    }
}

impl<T, C, S> Stream for HandshakeTransport<T, C, S>
where
    T: AsyncRead + AsyncWrite,
    T: Send + 'static,
    C: Decoder<Item = HandshakeFrame, Error = io::Error>,
    C: Encoder<Item = HandshakeFrame, Error = io::Error>,
    S: HandshakeStateTrait,
{
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<()>, io::Error> {
        let value = match self.upstream.poll() {
            Ok(Async::Ready(t)) => t,
            Ok(Async::NotReady) => return Ok(Async::NotReady),
            Err(e) => return Err(From::from(e)),
        };

        if let Some(frame) = value {
            if let Err(e) = self.handle_frame(frame) {
                let err = format!("failed to handle frame: {:?}", e);
                return Err(io::Error::new(io::ErrorKind::Other, err));
            }
            self.send_frames()?;
            Ok(Async::Ready(Some(())))
        } else {
            Ok(Async::Ready(None))
        }
    }
}

impl<T, C, S> Sink for HandshakeTransport<T, C, S>
where
    T: AsyncWrite,
    T: Send,
    C: Decoder<Item = HandshakeFrame, Error = io::Error>,
    C: Encoder<Item = HandshakeFrame, Error = io::Error>,
{
    type SinkItem = HandshakeFrame;
    type SinkError = io::Error;

    fn start_send(&mut self, item: HandshakeFrame) -> StartSend<HandshakeFrame, io::Error> {
        self.upstream.start_send(item)
    }

    fn poll_complete(&mut self) -> Poll<(), io::Error> {
        self.upstream.poll_complete()
    }
}

/// Implements a future of `HandshakeTransport`
///
/// This structure is used to perform the NTCP handshake and provide
/// a connected transport afterwards
struct TransportConnector<T, C, S> {
    transport: Option<HandshakeTransport<T, C, S>>,
}

impl<T, C, S> TransportConnector<T, C, S>
where
    Codec: From<C>,
{
    fn transmute_transport(transport: HandshakeTransport<T, C, S>) -> Framed<T, Codec> {
        let parts = transport.upstream.into_parts();
        let mut new_parts = FramedParts::new(parts.io, Codec::from(parts.codec));
        new_parts.read_buf = parts.read_buf;
        new_parts.write_buf = parts.write_buf;
        Framed::from_parts(new_parts)
    }
}

impl<T, C, S> Future for TransportConnector<T, C, S>
where
    T: AsyncRead + AsyncWrite,
    T: Send + 'static,
    C: Decoder<Item = HandshakeFrame, Error = io::Error>,
    C: Encoder<Item = HandshakeFrame, Error = io::Error>,
    Codec: From<C>,
    S: HandshakeStateTrait,
{
    type Item = Framed<T, Codec>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let mut transport = self.transport.take().unwrap();

        //we might have received a frame before here
        transport.send_and_handle_frames()?;

        if transport
            .state
            .as_ref()
            .map_or(false, |s| s.is_established())
        {
            return Ok(Async::Ready(TransportConnector::transmute_transport(
                transport,
            )));
        }

        match transport.poll()? {
            Async::Ready(Some(_)) => {
                if transport
                    .state
                    .as_ref()
                    .map_or(false, |s| s.is_established())
                {
                    // Upstream had frames available and we're connected, the transport is ready
                    Ok(Async::Ready(TransportConnector::transmute_transport(
                        transport,
                    )))
                } else {
                    // Upstream had frames but we're not yet connected, continue polling
                    let poll_ret = transport.poll();
                    self.transport = Some(transport);
                    poll_ret?;
                    Ok(Async::NotReady)
                }
            }
            _ => {
                // Upstream had no frames
                self.transport = Some(transport);
                Ok(Async::NotReady)
            }
        }
    }
}
