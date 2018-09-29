use bytes::BytesMut;
use cookie_factory::GenError;
use futures::{sink, stream::StreamFuture, Async, Future, Poll, Sink, Stream};
use nom::{Err, Offset};
use std::io;
use std::iter::repeat;
use std::ops::AddAssign;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio_codec::{Decoder, Encoder, Framed, FramedParts};
use tokio_io::{AsyncRead, AsyncWrite};

use super::{Codec, NTCP_MTU};
use crypto::{Aes256, Signature, SigningPrivateKey, AES_BLOCK_SIZE};
use data::{Hash, RouterIdentity};
use transport::DHSessionKeyBuilder;

mod frame;

macro_rules! try_poll {
    ($conn:expr, $expected:ident) => {
        match try_ready!($conn.poll().map_err(|(e, _)| e)) {
            (Some(HandshakeFrame::$expected(f)), c) => (c, f),
            (Some(_), _) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Unexpected handshake frame received",
                ));
            }
            (None, _) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Handshake connection terminated early",
                ));
            }
        }
    };
}

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
                                                "incomplete parse error".to_string(),
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
                _ => panic!("Couldn't serialize Signature message (Own RI?): {:?}", e),
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

//
// Inbound handshake protocol
//

enum IBHandshakeState<T>
where
    T: AsyncWrite,
{
    SessionRequest(StreamFuture<Framed<T, InboundHandshakeCodec>>),
    SessionCreated((sink::Send<Framed<T, InboundHandshakeCodec>>, SystemTime)),
    SessionConfirmA((StreamFuture<Framed<T, InboundHandshakeCodec>>, SystemTime)),
    SessionConfirmB(sink::Send<Framed<T, InboundHandshakeCodec>>),
}

pub struct IBHandshake<T>
where
    T: AsyncWrite,
{
    shared: SharedHandshakeState,
    state: IBHandshakeState<T>,
}

impl<T> IBHandshake<T>
where
    T: AsyncRead + AsyncWrite,
    T: Send + 'static,
{
    pub fn new(stream: T, own_ri: RouterIdentity, own_key: SigningPrivateKey) -> Self {
        // Generate a new DH pair
        let dh_key_builder = DHSessionKeyBuilder::new();
        let dh_y = dh_key_builder.get_pub();
        let mut iv_enc = [0u8; AES_BLOCK_SIZE];
        iv_enc.copy_from_slice(&dh_y[dh_y.len() - AES_BLOCK_SIZE..]);

        // TODO: Find a way to refer to the codec from here, to deduplicate state
        let codec = InboundHandshakeCodec::new(dh_key_builder, iv_enc);
        let state = IBHandshakeState::SessionRequest(codec.framed(stream).into_future());
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
            state,
        }
    }

    fn transmute_framed(framed: Framed<T, InboundHandshakeCodec>) -> Framed<T, Codec> {
        let parts = framed.into_parts();
        let mut new_parts = FramedParts::new(parts.io, Codec::from(parts.codec));
        new_parts.read_buf = parts.read_buf;
        new_parts.write_buf = parts.write_buf;
        Framed::from_parts(new_parts)
    }
}

impl<T> Future for IBHandshake<T>
where
    T: AsyncRead + AsyncWrite,
    T: Send + 'static,
{
    type Item = (RouterIdentity, Framed<T, Codec>);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            self.state = match self.state {
                IBHandshakeState::SessionRequest(ref mut f) => {
                    let (conn, sr) = try_poll!(f, SessionRequest);

                    // Part 1
                    debug!("Received SessionRequest");
                    // Check that Alice knows who she is trying to talk with, and
                    // that the X isn't corrupt
                    let mut hxxorhb = Hash::digest(&sr.dh_x[..]);
                    hxxorhb.xor(&self.shared.own_ri.hash());
                    if hxxorhb != sr.hash {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Invalid SessionRequest HXxorHB",
                        ));
                    }
                    // TODO check replays
                    let now = SystemTime::now();
                    let mut ts_b = now.duration_since(UNIX_EPOCH).expect("Time went backwards");
                    ts_b.add_assign(Duration::from_millis(500));
                    // Update local state
                    self.shared.dh_x = sr.dh_x;
                    self.shared.ts_b = ts_b.as_secs() as u32;

                    // Part 2
                    debug!("Sending SessionCreated");
                    let mut xy = Vec::from(&self.shared.dh_x[..]);
                    xy.extend_from_slice(&self.shared.dh_y);
                    let sc = HandshakeFrame::SessionCreated(SessionCreated {
                        dh_y: self.shared.dh_y.clone(),
                        hash: Hash::digest(&xy),
                        ts_b: self.shared.ts_b,
                    });

                    IBHandshakeState::SessionCreated((conn.send(sc), now))
                }
                IBHandshakeState::SessionCreated((ref mut f, rtt_timer)) => {
                    let conn = try_ready!(f.poll());
                    IBHandshakeState::SessionConfirmA((conn.into_future(), rtt_timer))
                }
                IBHandshakeState::SessionConfirmA((ref mut f, rtt_timer)) => {
                    let (conn, sca) = try_poll!(f, SessionConfirmA);

                    // Part 3
                    debug!("Received SessionConfirmA");
                    // Get peer skew
                    let rtt = rtt_timer.elapsed().expect("Time went backwards?");
                    debug!("Peer RTT: {:?}", rtt);
                    // Update local state
                    self.shared.ri_remote = Some(sca.ri_a);
                    self.shared.ts_a = sca.ts_a;
                    // Generate message to be verified
                    let msg = gen_session_confirm_sig_msg(&self.shared, true);
                    if let Err(e) = self
                        .shared
                        .ri_remote
                        .as_ref()
                        .unwrap()
                        .signing_key
                        .verify(&msg, &sca.sig)
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionRefused,
                            format!("Invalid SessionConfirmA signature: {:?}", e),
                        ));
                    }

                    // Part 4
                    debug!("Sending SessionConfirmB");
                    // Generate message to be signed
                    let msg = gen_session_confirm_sig_msg(&self.shared, false);
                    let sig = match self.shared.own_key.sign(&msg) {
                        Ok(sig) => sig,
                        Err(_) => {
                            return Err(io::Error::new(
                                io::ErrorKind::Other,
                                "Could not create SessionConfirmB signature",
                            ))
                        }
                    };
                    let scb = HandshakeFrame::SessionConfirmB(SessionConfirmB { sig });

                    IBHandshakeState::SessionConfirmB(conn.send(scb))
                }
                IBHandshakeState::SessionConfirmB(ref mut f) => {
                    let conn = try_ready!(f.poll());
                    return Ok(Async::Ready((
                        self.shared.ri_remote.take().unwrap(),
                        IBHandshake::transmute_framed(conn),
                    )));
                }
            }
        }
    }
}

//
// Outbound handshake protocol
//

enum OBHandshakeState<T>
where
    T: AsyncWrite,
{
    SessionRequest((sink::Send<Framed<T, OutboundHandshakeCodec>>, SystemTime)),
    SessionCreated((StreamFuture<Framed<T, OutboundHandshakeCodec>>, SystemTime)),
    SessionConfirmA(sink::Send<Framed<T, OutboundHandshakeCodec>>),
    SessionConfirmB(StreamFuture<Framed<T, OutboundHandshakeCodec>>),
}

pub struct OBHandshake<T>
where
    T: AsyncWrite,
{
    shared: SharedHandshakeState,
    state: OBHandshakeState<T>,
}

impl<T> OBHandshake<T>
where
    T: AsyncRead + AsyncWrite,
    T: Send + 'static,
{
    pub fn new(
        stream: T,
        own_ri: RouterIdentity,
        own_key: SigningPrivateKey,
        ri_remote: RouterIdentity,
    ) -> Self {
        // Generate a new DH pair
        let dh_key_builder = DHSessionKeyBuilder::new();
        let dh_x = dh_key_builder.get_pub();
        let mut hxxorhb = Hash::digest(&dh_x[..]);
        hxxorhb.xor(&ri_remote.hash());
        let mut iv_enc = [0u8; AES_BLOCK_SIZE];
        iv_enc.copy_from_slice(&hxxorhb.0[AES_BLOCK_SIZE..]);

        // TODO: Find a way to refer to the codec from here, to deduplicate state
        let codec = OutboundHandshakeCodec::new(dh_key_builder, iv_enc, ri_remote.clone());
        let conn = codec.framed(stream);

        // Part 1
        debug!("Sending SessionRequest");
        let sr = HandshakeFrame::SessionRequest(SessionRequest {
            dh_x: dh_x.clone(),
            hash: hxxorhb,
        });
        let state = OBHandshakeState::SessionRequest((conn.send(sr), SystemTime::now()));

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
            state,
        }
    }

    fn transmute_framed(framed: Framed<T, OutboundHandshakeCodec>) -> Framed<T, Codec> {
        let parts = framed.into_parts();
        let mut new_parts = FramedParts::new(parts.io, Codec::from(parts.codec));
        new_parts.read_buf = parts.read_buf;
        new_parts.write_buf = parts.write_buf;
        Framed::from_parts(new_parts)
    }
}

impl<T> Future for OBHandshake<T>
where
    T: AsyncRead + AsyncWrite,
    T: Send + 'static,
{
    type Item = (RouterIdentity, Framed<T, Codec>);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            self.state = match self.state {
                OBHandshakeState::SessionRequest((ref mut f, rtt_timer)) => {
                    let conn = try_ready!(f.poll());
                    OBHandshakeState::SessionCreated((conn.into_future(), rtt_timer))
                }
                OBHandshakeState::SessionCreated((ref mut f, rtt_timer)) => {
                    let (conn, sc) = try_poll!(f, SessionCreated);

                    // Part 2
                    debug!("Received SessionCreated");
                    // Get peer skew
                    let rtt = rtt_timer.elapsed().expect("Time went backwards?");
                    debug!("Peer RTT: {:?}", rtt);
                    let now = SystemTime::now();
                    let mut ts_a = now.duration_since(UNIX_EPOCH).expect("Time went backwards");
                    ts_a.add_assign(Duration::from_millis(500));
                    // Update local state
                    self.shared.dh_y = sc.dh_y;
                    self.shared.ts_a = ts_a.as_secs() as u32;
                    self.shared.ts_b = sc.ts_b;

                    // Generate message to be signed
                    let msg = gen_session_confirm_sig_msg(&self.shared, false);
                    // Check part 2 (which happens to be hash of first part of signed message)
                    let hxy = Hash::digest(&msg[..512]);
                    if hxy != sc.hash {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Invalid SessionCreated hash",
                        ));
                    }

                    // Part 3
                    debug!("Sending SessionConfirmA");
                    let sig = match self.shared.own_key.sign(&msg) {
                        Ok(sig) => sig,
                        Err(_) => {
                            return Err(io::Error::new(
                                io::ErrorKind::Other,
                                "Could not create SessionConfirmA signature",
                            ))
                        }
                    };
                    let sca = HandshakeFrame::SessionConfirmA(SessionConfirmA {
                        ri_a: self.shared.own_ri.clone(),
                        ts_a: self.shared.ts_a,
                        sig,
                    });
                    OBHandshakeState::SessionConfirmA(conn.send(sca))
                }
                OBHandshakeState::SessionConfirmA(ref mut f) => {
                    let conn = try_ready!(f.poll());
                    OBHandshakeState::SessionConfirmB(conn.into_future())
                }
                OBHandshakeState::SessionConfirmB(ref mut f) => {
                    let (conn, scb) = try_poll!(f, SessionConfirmB);

                    // Part 4
                    debug!("Received SessionConfirmB");
                    // Generate message to be verified
                    let msg = gen_session_confirm_sig_msg(&self.shared, true);
                    if let Err(e) = self
                        .shared
                        .ri_remote
                        .as_ref()
                        .unwrap()
                        .signing_key
                        .verify(&msg, &scb.sig)
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionRefused,
                            format!("Invalid SessionConfirmB signature: {:?}", e),
                        ));
                    }

                    return Ok(Async::Ready((
                        self.shared.ri_remote.take().unwrap(),
                        OBHandshake::transmute_framed(conn),
                    )));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{IBHandshake, IBHandshakeState, OBHandshake, OBHandshakeState};
    use transport::tests::{AliceNet, BobNet, NetworkCable};

    use futures::{Async, Future};

    use data::RouterSecretKeys;

    macro_rules! test_poll {
        ($node:expr) => {
            match $node.poll() {
                Ok(Async::NotReady) => (),
                Ok(Async::Ready(_)) => panic!("Unexpectedly ready early!"),
                Err(e) => panic!("Unexpected error: {}", e),
            }
        };
    }

    macro_rules! test_state {
        ($alice:expr, $alice_state:ident, $bob:expr, $bob_state:ident) => {
            match (&$alice.state, &$bob.state) {
                (OBHandshakeState::$alice_state(_), IBHandshakeState::$bob_state(_)) => (),
                _ => panic!(),
            }
        };
    }

    #[test]
    fn ntcp_handshake() {
        // Generate key material
        let (alice_rid, alice_sk) = {
            let sk = RouterSecretKeys::new();
            (sk.rid, sk.signing_private_key)
        };
        let (bob_rid, bob_sk) = {
            let sk = RouterSecretKeys::new();
            (sk.rid, sk.signing_private_key)
        };

        // Set up the network
        let cable = NetworkCable::new();
        let alice_net = AliceNet::new(cable.clone());
        let bob_net = BobNet::new(cable);

        // Set up the handshake
        let mut alice = OBHandshake::new(alice_net, alice_rid, alice_sk, bob_rid.clone());
        let mut bob = IBHandshake::new(bob_net, bob_rid, bob_sk);
        test_state!(alice, SessionRequest, bob, SessionRequest);

        // Alice -> SessionRequest
        test_poll!(alice);
        test_state!(alice, SessionCreated, bob, SessionRequest);

        // Bob <- SessionRequest
        // Bob -> SessionCreated
        test_poll!(bob);
        test_state!(alice, SessionCreated, bob, SessionConfirmA);

        // Alice <- SessionCreated
        // Alice -> SessionConfirmA
        test_poll!(alice);
        test_state!(alice, SessionConfirmB, bob, SessionConfirmA);

        // Bob <- SessionConfirmA
        // Bob -> SessionConfirmB
        let bob_conn = bob.poll();

        // Alice <- SessionConfirmB
        let alice_conn = alice.poll();

        // Both halves should now be ready
        match (alice_conn, bob_conn) {
            (Ok(Async::Ready(_)), Ok(Async::Ready(_))) => (),
            _ => panic!(),
        }
    }
}
