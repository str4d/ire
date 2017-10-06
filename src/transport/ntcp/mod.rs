use cookie_factory::GenError;
use bytes::BytesMut;
use nom::{IResult, Offset};
use std::io;
use std::iter::repeat;
use tokio_io::codec::{Decoder, Encoder};

use crypto::{AES_BLOCK_SIZE, Aes256, Signature};
use data::{Hash, RouterIdentity};
use i2np::Message;
use super::DHSessionKeyBuilder;

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

#[derive(Clone,Copy,Debug,Eq,PartialEq)]
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
                              .decrypt_blocks(&mut buf[self.decrypted..]) {
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
                    return Err(io::Error::new(io::ErrorKind::Other,
                                              format!("parse error: {:?}", e)))
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
        let length = buf.len();
        if length < NTCP_MTU {
            buf.extend(repeat(0).take(NTCP_MTU - length));
        }

        let res = match (self.state, frame) {
            (HandshakeState::SessionCreated, HandshakeFrame::SessionCreated(ref sc)) => {
                // Set up cryptor
                let session_key =
                    self.dh_key_builder.build_session_key(array_ref![self.dh_x, 0, 256]);
                self.aes = Some(Aes256::new(&session_key, &self.iv_enc, &self.iv_dec));
                // Serialise inner part of SessionCreated
                let mut tmp = [0u8; 48];
                match frame::gen_session_created_dec((&mut tmp, 0), &sc).map(|tup| tup.1) {
                    Ok(inner_sz) => {
                        // Encrypt message in-place
                        match self.aes
                                  .as_mut()
                                  .unwrap()
                                  .encrypt_blocks(&mut tmp) {
                            Some(end) if end == inner_sz => {
                                // Serialise outer SessionCreated
                                match frame::gen_session_created_enc((buf, 0), &sc.dh_y, &tmp)
                                          .map(|tup| tup.1) {
                                    Ok(sz) => {
                                        buf.truncate(sz);
                                        Ok(())
                                    }
                                    Err(e) => Err(e),
                                }
                            }
                            _ => {
                                return Err(io::Error::new(io::ErrorKind::InvalidData,
                                                          "invalid serialization"));
                            }
                        }
                    }
                    Err(e) => Err(e),
                }
            }
            (HandshakeState::SessionConfirmB, HandshakeFrame::SessionConfirmB(ref scb)) => {
                match frame::gen_session_confirm_b((buf, 0), &scb).map(|tup| tup.1) {
                    Ok(sz) => {
                        buf.truncate(sz);
                        // Encrypt message in-place
                        match self.aes
                                  .as_mut()
                                  .unwrap()
                                  .encrypt_blocks(buf) {
                            Some(end) if end == sz => Ok(()),
                            _ => {
                                return Err(io::Error::new(io::ErrorKind::InvalidData,
                                                          "invalid serialization"))
                            }
                        }
                    }
                    Err(e) => Err(e),
                }
            }
            _ => {
                return Err(io::Error::new(io::ErrorKind::InvalidInput,
                                          "incorrect state for sending"))
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
            Err(e) => {
                match e {
                    GenError::BufferTooSmall(sz) => {
                        Err(io::Error::new(io::ErrorKind::InvalidData,
                                           format!("message ({}) larger than MTU ({})",
                                                   sz,
                                                   NTCP_MTU)))
                    }
                    GenError::InvalidOffset |
                    GenError::CustomError(_) |
                    GenError::NotYetImplemented => {
                        Err(io::Error::new(io::ErrorKind::InvalidData, "could not generate"))
                    }
                }
            }
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
    fn new(dh_key_builder: DHSessionKeyBuilder,
           iv_enc: [u8; AES_BLOCK_SIZE],
           ri_remote: RouterIdentity)
           -> Self {
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
                            return Err(io::Error::new(io::ErrorKind::Other,
                                                      format!("parse error: {:?}", e)))
                        }
                        IResult::Done(i, mut sce) => {
                            // Set up cryptor
                            let session_key = self.dh_key_builder
                                .build_session_key(array_ref![sce.0, 0, 256]);
                            self.aes = Some(Aes256::new(&session_key,
                                                        &self.iv_enc,
                                                        array_ref![sce.0,
                                                                   sce.0.len() - AES_BLOCK_SIZE,
                                                                   AES_BLOCK_SIZE]));
                            // Decrypt remainder of SessionCreated message
                            match self.aes
                                      .as_mut()
                                      .unwrap()
                                      .decrypt_blocks(&mut sce.1) {
                                Some(end) if end == sce.1.len() => {
                                    match frame::session_created_dec(&sce.1) {
                                        IResult::Incomplete(_) => {
                                            return Err(io::Error::new(io::ErrorKind::Other,
                                                                      format!("incomplete parse error")))
                                        }
                                        IResult::Error(e) => {
                                            return Err(io::Error::new(io::ErrorKind::Other,
                                                                      format!("parse error: {:?}",
                                                                              e)))
                                        }
                                        IResult::Done(_, scd) => {
                                            IResult::Done(i, HandshakeFrame::SessionCreated(SessionCreated {
                                                dh_y: sce.0,
                                                hash: scd.0,
                                                ts_b: scd.1,
                                            }))
                                        }
                                    }
                                }
                                Some(sz) => {
                                    return Err(io::Error::new(io::ErrorKind::Other,
                                                              format!("incomplete encrypt error, encrypted {} out of {}",
                                                                      sz,
                                                                      sce.1.len())))
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
                              .decrypt_blocks(&mut buf[self.decrypted..]) {
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
                    return Err(io::Error::new(io::ErrorKind::Other,
                                              format!("parse error: {:?}", e)))
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
        let length = buf.len();
        if length < NTCP_MTU {
            buf.extend(repeat(0).take(NTCP_MTU - length));
        }

        let res = match (self.state, frame) {
            (HandshakeState::SessionRequest, HandshakeFrame::SessionRequest(ref sr)) => {
                match frame::gen_session_request((buf, 0), &sr).map(|tup| tup.1) {
                    Ok(sz) => {
                        buf.truncate(sz);
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
            (HandshakeState::SessionConfirmA, HandshakeFrame::SessionConfirmA(ref sca)) => {
                match frame::gen_session_confirm_a((buf, 0), &sca).map(|tup| tup.1) {
                    Ok(sz) => {
                        buf.truncate(sz);
                        // Encrypt message in-place
                        match self.aes
                                  .as_mut()
                                  .unwrap()
                                  .encrypt_blocks(buf) {
                            Some(end) if end == sz => Ok(()),
                            _ => {
                                return Err(io::Error::new(io::ErrorKind::InvalidData,
                                                          "invalid serialization"))
                            }
                        }
                    }
                    Err(e) => Err(e),
                }
            }
            _ => {
                return Err(io::Error::new(io::ErrorKind::InvalidInput,
                                          "incorrect state for sending"))
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
            Err(e) => {
                match e {
                    GenError::BufferTooSmall(sz) => {
                        Err(io::Error::new(io::ErrorKind::InvalidData,
                                           format!("message ({}) larger than MTU ({})",
                                                   sz,
                                                   NTCP_MTU)))
                    }
                    GenError::InvalidOffset |
                    GenError::CustomError(_) |
                    GenError::NotYetImplemented => {
                        Err(io::Error::new(io::ErrorKind::InvalidData, "could not generate"))
                    }
                }
            }
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
                return Err(io::Error::new(io::ErrorKind::Other, format!("parse error: {:?}", e)))
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
        let length = buf.len();
        if length < NTCP_MTU {
            buf.extend(repeat(0).take(NTCP_MTU - length));
        }

        match frame::gen_frame((buf, 0), &frame).map(|tup| tup.1) {
            Ok(sz) => {
                buf.truncate(sz);
                // Encrypt message in-place
                match self.aes.encrypt_blocks(buf) {
                    Some(end) if end == sz => Ok(()),
                    _ => Err(io::Error::new(io::ErrorKind::InvalidData, "invalid serialization")),
                }
            }
            Err(e) => {
                match e {
                    GenError::BufferTooSmall(sz) => {
                        Err(io::Error::new(io::ErrorKind::InvalidData,
                                           format!("message ({}) larger than MTU ({})",
                                                   sz,
                                                   NTCP_MTU)))
                    }
                    GenError::InvalidOffset |
                    GenError::CustomError(_) |
                    GenError::NotYetImplemented => {
                        Err(io::Error::new(io::ErrorKind::InvalidData, "could not generate"))
                    }
                }
            }
        }
    }
}
