use bytes::BytesMut;
use cookie_factory::GenError;
use futures::{sync::mpsc, task, Async, Future, Poll, Stream};
use i2p_snow::{self, Builder};
use nom::Err;
use rand::{self, Rng};
use siphasher::sip::SipHasher;
use std::fmt;
use std::fs::File;
use std::hash::Hasher;
use std::io::{self, Read, Write};
use std::iter::repeat;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio;
use tokio::net::{TcpListener, TcpStream};
use tokio_codec::{Decoder, Encoder};
use tokio_io::IoFuture;
use tokio_timer::Deadline;

use super::session::{EngineRx, EngineTx, Session, SessionRefs, SessionState};
use constants::I2P_BASE64;
use data::{I2PString, RouterAddress, RouterIdentity, RouterInfo};
use i2np::Message;

mod frame;
mod handshake;

lazy_static! {
    pub static ref NTCP2_STYLE: I2PString = I2PString::new("NTCP2");
    pub static ref NTCP2_VERSION: I2PString = I2PString::new("2");
    pub static ref NTCP2_OPT_V: I2PString = I2PString::new("v");
    pub static ref NTCP2_OPT_S: I2PString = I2PString::new("s");
    pub static ref NTCP2_OPT_I: I2PString = I2PString::new("i");
    pub static ref NTCP2_NOISE_PROTOCOL_NAME: &'static str =
        "Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256";
}

// Max NTCP2 message size is ~64kB
const NTCP2_MTU: usize = 65535;

macro_rules! io_err {
    ($err_kind:ident, $err_msg:expr) => {
        Err(io::Error::new(io::ErrorKind::$err_kind, $err_msg))
    };
}

//
// Message transport
//

#[derive(PartialEq)]
pub struct RouterInfoFlags {
    flood: bool,
}

#[derive(PartialEq)]
pub enum Block {
    DateTime(u32),
    Options(Vec<u8>),
    RouterInfo(RouterInfo, RouterInfoFlags),
    Message(Message),
    Termination(u64, u8, Vec<u8>),
    Padding(u16),
    Unknown(u8, Vec<u8>),
}

impl fmt::Debug for Block {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Block::DateTime(ts) => format!("DateTime ({})", ts).fmt(formatter),
            &Block::Options(_) => "Options".fmt(formatter),
            &Block::RouterInfo(ref ri, ref flags) => format!(
                "RouterInfo ({}, flood: {})",
                ri.router_id.hash(),
                flags.flood
            ).fmt(formatter),
            &Block::Message(_) => "I2NP message".fmt(formatter),
            &Block::Termination(_, rsn, _) => {
                format!("Termination (reason: {})", rsn).fmt(formatter)
            }
            &Block::Padding(size) => format!("Padding ({} bytes)", size).fmt(formatter),
            &Block::Unknown(blk, ref data) => {
                format!("Unknown (type: {}, {} bytes)", blk, data.len()).fmt(formatter)
            }
        }
    }
}

type Frame = Vec<Block>;

pub struct Codec {
    noise: i2p_snow::Session,
    noise_buf: [u8; NTCP2_MTU],
    enc_len_masker: SipHasher,
    enc_len_iv: u64,
    dec_len_masker: SipHasher,
    dec_len_iv: u64,
    next_len: Option<usize>,
}

impl Decoder for Codec {
    type Item = Frame;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> io::Result<Option<Frame>> {
        if let None = self.next_len {
            if buf.len() < 2 {
                return Ok(None);
            }

            // Update masker state
            let mut masker = self.dec_len_masker.clone();
            masker.write_u64(self.dec_len_iv);
            self.dec_len_iv = masker.finish();

            // Read the length
            let mut msg_len = ((buf[0] as usize) << 8) + (buf[1] as usize);
            msg_len ^= (self.dec_len_iv & 0xffff) as usize;

            buf.split_to(2);
            self.next_len = Some(msg_len);
        }

        match self.next_len {
            Some(len) if buf.len() >= len => {
                // Read the frame
                let frame_len = match self.noise.read_message(&buf[..len], &mut self.noise_buf) {
                    Ok(len) => len,
                    Err(e) => return io_err!(Other, format!("Decryption error: {:?}", e)),
                };

                // Parse the frame
                let f = match frame::frame(&self.noise_buf[..frame_len]) {
                    Err(Err::Incomplete(n)) => {
                        return io_err!(
                            Other,
                            format!("received incomplete message, needed: {:?}", n)
                        )
                    }
                    Err(Err::Error(e)) | Err(Err::Failure(e)) => {
                        return io_err!(Other, format!("parse error: {:?}", e))
                    }
                    Ok((_, frame)) => frame,
                };

                buf.split_to(len);
                self.next_len = None;

                Ok(Some(f))
            }
            _ => Ok(None),
        }
    }
}

impl Encoder for Codec {
    type Item = Frame;
    type Error = io::Error;

    fn encode(&mut self, frame: Frame, buf: &mut BytesMut) -> io::Result<()> {
        match frame::gen_frame((&mut self.noise_buf, 0), &frame).map(|tup| tup.1) {
            Ok(sz) => {
                let mut msg_len = sz + 16;

                let start = buf.len();
                buf.extend(repeat(0).take(2 + msg_len));

                // Update masker state
                let mut masker = self.enc_len_masker.clone();
                masker.write_u64(self.enc_len_iv);
                self.enc_len_iv = masker.finish();

                // Mask the length
                let masked_len = msg_len ^ (self.enc_len_iv & 0xffff) as usize;

                buf[start] = (masked_len >> 8) as u8;
                buf[start + 1] = (masked_len & 0xff) as u8;
                match self
                    .noise
                    .write_message(&self.noise_buf[..sz], &mut buf[start + 2..])
                {
                    Ok(len) if len == msg_len => Ok(()),
                    Ok(len) => io_err!(
                        InvalidData,
                        format!("encrypted frame is unexpected size: {}", len)
                    ),
                    Err(e) => io_err!(Other, format!("encryption error: {:?}", e)),
                }
            }
            Err(e) => match e {
                GenError::BufferTooSmall(sz) => io_err!(
                    InvalidData,
                    format!("message ({}) larger than MTU ({})", sz, NTCP2_MTU)
                ),
                GenError::InvalidOffset
                | GenError::CustomError(_)
                | GenError::NotYetImplemented => io_err!(InvalidData, "could not generate"),
            },
        }
    }
}

//
// Connection management engine
//

pub struct Engine {
    addr: SocketAddr,
    static_private_key: Vec<u8>,
    static_public_key: Vec<u8>,
    aesobfse_iv: [u8; 16],
    state: SessionState<Frame>,
    inbound: (EngineTx<Frame>, EngineRx<Frame>),
    outbound: (EngineTx<Frame>, EngineRx<Frame>),
}

impl Engine {
    pub fn new(addr: SocketAddr) -> Self {
        let builder: Builder = Builder::new(NTCP2_NOISE_PROTOCOL_NAME.parse().unwrap());
        let dh = builder.generate_keypair().unwrap();

        let mut aesobfse_iv = [0; 16];
        let mut rng = rand::thread_rng();
        rng.fill(&mut aesobfse_iv[..]);

        Engine {
            addr,
            static_private_key: dh.private,
            static_public_key: dh.public,
            aesobfse_iv,
            state: SessionState::new(),
            inbound: mpsc::unbounded(),
            outbound: mpsc::unbounded(),
        }
    }

    pub fn from_file(addr: SocketAddr, path: &str) -> io::Result<Self> {
        let mut keys = File::open(path)?;
        let mut data: Vec<u8> = Vec::new();
        keys.read_to_end(&mut data)?;

        let mut static_private_key = Vec::with_capacity(32);
        let mut static_public_key = Vec::with_capacity(32);
        let mut aesobfse_iv = [0; 16];

        static_private_key.extend_from_slice(&data[..32]);
        static_public_key.extend_from_slice(&data[32..64]);
        aesobfse_iv.copy_from_slice(&data[64..]);

        Ok(Engine {
            addr,
            static_private_key,
            static_public_key,
            aesobfse_iv,
            state: SessionState::new(),
            inbound: mpsc::unbounded(),
            outbound: mpsc::unbounded(),
        })
    }

    pub fn to_file(&self, path: &str) -> io::Result<()> {
        let mut data = Vec::with_capacity(96);
        data.write(&self.static_private_key)?;
        data.write(&self.static_public_key)?;
        data.write(&self.aesobfse_iv)?;
        let mut keys = File::create(path)?;
        keys.write(&data).map(|_| ())
    }

    pub fn handle(&self) -> EngineTx<Frame> {
        self.outbound.0.clone()
    }

    pub fn address(&self) -> RouterAddress {
        let mut ra = RouterAddress::new(&NTCP2_STYLE, self.addr);
        ra.set_option(NTCP2_OPT_V.clone(), NTCP2_VERSION.clone());
        ra.set_option(
            NTCP2_OPT_S.clone(),
            I2PString(I2P_BASE64.encode(&self.static_public_key)),
        );
        ra.set_option(
            NTCP2_OPT_I.clone(),
            I2PString(I2P_BASE64.encode(&self.aesobfse_iv)),
        );
        ra
    }

    pub fn listen(&self, own_rid: RouterIdentity) -> IoFuture<()> {
        // Bind to the address
        let listener = TcpListener::bind(&self.addr).unwrap();
        let static_key = self.static_private_key.clone();
        let aesobfse_key = own_rid.hash().0;
        let aesobfse_iv = self.aesobfse_iv.clone();

        // Give each incoming connection the references it needs
        let session_refs = SessionRefs::new(self.state.clone(), self.inbound.0.clone());
        let conns = listener.incoming().zip(session_refs);

        // For each incoming connection:
        Box::new(conns.for_each(move |(conn, (state, engine))| {
            info!("Incoming connection!");
            // Execute the handshake
            let conn = handshake::IBHandshake::new(conn, &static_key, &aesobfse_key, &aesobfse_iv);

            // Once connected:
            let process_conn = conn.and_then(|(ri, conn)| Session::new(ri, conn, state, engine));

            tokio::spawn(process_conn.map_err(|e| error!("Error while listening: {:?}", e)));
            Ok(())
        }))
    }

    pub fn connect(&self, own_ri: RouterInfo, peer_ri: RouterInfo) -> io::Result<IoFuture<()>> {
        // Connect to the peer
        let transport = match handshake::OBHandshake::new(
            |sa| Box::new(TcpStream::connect(sa)),
            &self.static_private_key,
            own_ri,
            peer_ri,
        ) {
            Ok(t) => t,
            Err(e) => return io_err!(InvalidData, e),
        };

        // Add a timeout
        let timed = Deadline::new(transport, Instant::now() + Duration::new(10, 0))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e));

        // Once connected:
        let state = self.state.clone();
        let engine = self.inbound.0.clone();
        Ok(Box::new(timed.and_then(|(ri, conn)| {
            let session = Session::new(ri, conn, state, engine);
            tokio::spawn(session.map_err(|_| ()));
            Ok(())
        })))
    }
}

impl Future for Engine {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<(), ()> {
        // Write frames
        const FRAMES_PER_TICK: usize = 10;
        for i in 0..FRAMES_PER_TICK {
            match self.outbound.1.poll().unwrap() {
                Async::Ready(Some((hash, frame))) => {
                    self.state.get(&hash, |s| match s {
                        Some(session) => {
                            session.unbounded_send(frame).unwrap();
                        }
                        None => error!("No open session for {}", hash), // TODO: Open session instead of dropping
                    });

                    // If this is the last iteration, the loop will break even
                    // though there could still be frames to read. Because we did
                    // not reach `Async::NotReady`, we have to notify ourselves
                    // in order to tell the executor to schedule the task again.
                    if i + 1 == FRAMES_PER_TICK {
                        task::current().notify();
                    }
                }
                _ => break,
            }
        }

        // Read frames
        while let Async::Ready(f) = self.inbound.1.poll()? {
            if let Some((hash, frame)) = f {
                // TODO: Do something
                debug!("Received frame from {}: {:?}", hash, frame);
            } else {
                // EOF was reached. The remote peer has disconnected.
                return Ok(Async::Ready(()));
            }
        }

        // We know we got a `NotReady` from both `self.outbound.1` and `self.inbound.1`,
        // so the contract is respected.
        Ok(Async::NotReady)
    }
}
