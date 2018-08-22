use bytes::BytesMut;
use cookie_factory::GenError;
use futures::{Future, Stream};
use nom::Err;
use rand::{self, Rng};
use siphasher::sip::SipHasher;
use snow::{self, Builder};
use std::fmt;
use std::fs::File;
use std::hash::Hasher;
use std::io::{self, Read, Write};
use std::iter::repeat;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio;
use tokio::net::{TcpListener, TcpStream};
use tokio_codec::{Decoder, Encoder, Framed};
use tokio_io::IoFuture;
use tokio_timer::Deadline;

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
    noise: snow::Session,
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

        // For each incoming connection:
        Box::new(listener.incoming().for_each(move |conn| {
            info!("Incoming connection!");
            let process_conn =
                handshake::IBHandshake::new(conn, &static_key, &aesobfse_key, &aesobfse_iv)
                    .and_then(|f| {
                        f.for_each(|frame| {
                            for block in frame {
                                debug!("Received block: {:?}", block);
                            }

                            Ok(())
                        })
                    });
            tokio::spawn(process_conn.map_err(|e| error!("Error while listening: {:?}", e)));
            Ok(())
        }))
    }

    pub fn connect(
        &self,
        own_ri: RouterInfo,
        peer_ri: RouterInfo,
    ) -> io::Result<IoFuture<Framed<TcpStream, Codec>>> {
        // Connect to the peer
        // Return a transport ready for sending and receiving Frames
        // The layer above will convert I2NP packets to Frames
        // (or should the Engine handle timesync packets itself?)
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

        Ok(Box::new(timed))
    }
}
