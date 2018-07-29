use byteorder::{LittleEndian, ReadBytesExt};
use bytes::BytesMut;
use cookie_factory::GenError;
use futures::{Future, Stream};
use nom::Err;
use rand::{self, Rng};
use siphasher::sip::SipHasher;
use snow::{self, Builder};
use std::fmt;
use std::hash::Hasher;
use std::io;
use std::iter::repeat;
use std::net::SocketAddr;
use std::ops::AddAssign;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio;
use tokio::net::{TcpListener, TcpStream};
use tokio_codec::{Decoder, Encoder, Framed};
use tokio_io::{self, IoFuture};
use tokio_timer::Deadline;

use super::ntcp::NTCP_STYLE;
use constants::I2P_BASE64;
use data::{I2PString, RouterAddress, RouterIdentity, RouterInfo};
use i2np::Message;

mod frame;

lazy_static! {
    pub static ref NTCP2_STYLE: I2PString = I2PString::new("NTCP2");
    pub static ref NTCP2_OPT_V: I2PString = I2PString::new("v");
    pub static ref NTCP2_OPT_S: I2PString = I2PString::new("s");
    pub static ref NTCP2_OPT_I: I2PString = I2PString::new("i");
    pub static ref NTCP2_NOISE_PROTOCOL_NAME: &'static str =
        "Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256";
}

// Max NTCP2 message size is ~64kB
const NTCP2_MTU: usize = 65535;

const SESSION_REQUEST_PT_LEN: usize = 16;
const SESSION_REQUEST_CT_LEN: usize = 32 + SESSION_REQUEST_PT_LEN + 16;
const SESSION_CREATED_PT_LEN: usize = 16;
const SESSION_CREATED_CT_LEN: usize = 32 + SESSION_CREATED_PT_LEN + 16;

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

            // Read the length
            let mut msg_len = ((buf[0] as usize) << 8) + (buf[1] as usize);
            msg_len ^= (self.dec_len_iv & 0xffff) as usize;

            // Update masker state
            let mut masker = self.dec_len_masker.clone();
            masker.write_u64(self.dec_len_iv);
            self.dec_len_iv = masker.finish();

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

                let masked_len = msg_len ^ (self.enc_len_iv & 0xffff) as usize;

                // Update masker state
                let mut masker = self.enc_len_masker.clone();
                masker.write_u64(self.enc_len_iv);
                self.enc_len_iv = masker.finish();

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

    pub fn address(&self) -> RouterAddress {
        let mut ra = RouterAddress::new(&NTCP2_STYLE, self.addr);
        ra.set_option(NTCP2_OPT_V.clone(), I2PString::new("2"));
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

            // Initialize our responder NoiseSession using a builder.
            let builder: Builder = Builder::new(NTCP2_NOISE_PROTOCOL_NAME.parse().unwrap());
            let mut noise = builder
                .local_private_key(&static_key)
                .aesobfse(&aesobfse_key, &aesobfse_iv)
                .enable_ask()
                .build_responder()
                .unwrap();

            let process_conn = tokio_io::io::read_exact(conn, vec![0u8; SESSION_REQUEST_CT_LEN])
                .and_then(|(conn, msg)| {
                    // <- e, es
                    debug!("S <- e, es");
                    let mut buf = [0u8; SESSION_REQUEST_PT_LEN];
                    noise.read_message(&msg, &mut buf).unwrap();

                    // SessionRequest
                    let (padlen, sclen, ts_a) = match frame::session_request(&buf) {
                        Err(e) => {
                            return io_err!(Other, format!("SessionRequest parse error: {:?}", e))
                        }
                        Ok((_, (ver, _, _, _))) if ver != 2 => {
                            return io_err!(InvalidData, "Unsupported version")
                        }
                        Ok((_, (_, padlen, sclen, ts_a))) => {
                            (padlen as usize, sclen as usize, ts_a)
                        }
                    };

                    Ok(tokio_io::io::read_exact(conn, vec![0u8; padlen])
                        .map(move |(c, m)| (c, noise, sclen, m)))
                })
                .and_then(|f| f)
                .and_then(|(conn, mut noise, sclen, padding)| {
                    noise.set_h_data(2, &padding).unwrap();

                    let now = SystemTime::now();
                    let mut ts_b = now.duration_since(UNIX_EPOCH).expect("Time went backwards");
                    ts_b.add_assign(Duration::from_millis(500));
                    let ts_b = ts_b.as_secs() as u32;

                    let mut rng = rand::thread_rng();
                    // TODO: Sample padding sizes from an appropriate distribution
                    let sc_padlen = rng.gen_range(0, 16);

                    // SessionCreated
                    let mut sc_buf = [0u8; SESSION_CREATED_PT_LEN];
                    match frame::gen_session_created((&mut sc_buf, 0), sc_padlen, ts_b)
                        .map(|tup| tup.1)
                    {
                        Ok(sz) if sz == sc_buf.len() => (),
                        Ok(_) => panic!("Size mismatch"),
                        Err(e) => match e {
                            GenError::BufferTooSmall(_) => panic!("Size mismatch"),
                            GenError::InvalidOffset
                            | GenError::CustomError(_)
                            | GenError::NotYetImplemented => {
                                return io_err!(InvalidData, "could not generate")
                            }
                        },
                    };

                    // -> e, ee
                    debug!("S -> e, ee");
                    let mut buf = vec![0u8; SESSION_CREATED_CT_LEN + sc_padlen as usize];
                    noise.write_message(&sc_buf, &mut buf).unwrap();
                    rng.fill(&mut buf[SESSION_CREATED_CT_LEN..]);
                    noise.set_h_data(3, &buf[SESSION_CREATED_CT_LEN..]).unwrap();

                    Ok(tokio_io::io::write_all(conn, buf)
                        .and_then(move |(conn, _)| {
                            tokio_io::io::read_exact(conn, vec![0u8; sclen + 48])
                        })
                        .map(move |(c, m)| (c, noise, now, m)))
                })
                .and_then(|f| f)
                .and_then(|(conn, mut noise, rtt_timer, msg)| {
                    // <- s, se
                    debug!("S <- s, se");
                    let mut buf = vec![0u8; msg.len()];
                    let len = noise.read_message(&msg, &mut buf).unwrap();

                    // SessionConfirmed
                    let ri_a = match frame::session_confirmed(&buf[..len]) {
                        Err(Err::Incomplete(n)) => {
                            return io_err!(
                                Other,
                                format!("received incomplete SessionConfirmed, needed: {:?}", n)
                            )
                        }
                        Err(Err::Error(e)) | Err(Err::Failure(e)) => {
                            return io_err!(Other, format!("SessionConfirmed parse error: {:?}", e))
                        }
                        Ok((_, ri_a)) => ri_a,
                    };

                    // Get peer skew
                    let rtt = rtt_timer.elapsed().expect("Time went backwards?");
                    debug!("Peer RTT: {:?}", rtt);

                    // Prepare length obfuscation keys and IVs
                    let (ek0, ek1, eiv, dk0, dk1, div) = {
                        let label = String::from("siphash");
                        noise.initialize_ask(vec![label.clone()]).unwrap();
                        let (ask0, ask1) = noise.finalize_ask(&label).unwrap();
                        let mut erdr = io::Cursor::new(&ask1); // Bob to Alice
                        let mut drdr = io::Cursor::new(&ask0); // Alice to Bob

                        (
                            erdr.read_u64::<LittleEndian>().unwrap(),
                            erdr.read_u64::<LittleEndian>().unwrap(),
                            erdr.read_u64::<LittleEndian>().unwrap(),
                            drdr.read_u64::<LittleEndian>().unwrap(),
                            drdr.read_u64::<LittleEndian>().unwrap(),
                            drdr.read_u64::<LittleEndian>().unwrap(),
                        )
                    };

                    // Transition the state machine into transport mode now that the handshake is complete.
                    let noise = noise.into_transport_mode().unwrap();
                    info!("Connection established!");

                    let codec = Codec {
                        noise,
                        noise_buf: [0u8; NTCP2_MTU],
                        enc_len_masker: SipHasher::new_with_keys(ek0, ek1),
                        enc_len_iv: eiv,
                        dec_len_masker: SipHasher::new_with_keys(dk0, dk1),
                        dec_len_iv: div,
                        next_len: None,
                    };

                    Ok(codec.framed(conn).for_each(|frame| {
                        for block in frame {
                            debug!("Received block: {:?}", block);
                        }

                        Ok(())
                    }))
                })
                .and_then(|f| f);

            tokio::spawn(process_conn.map_err(|e| error!("Error while listening: {:?}", e)));

            Ok(())
        }))
    }

    pub fn connect(
        &self,
        own_ri: RouterInfo,
        peer_ri: RouterInfo,
    ) -> io::Result<IoFuture<Framed<TcpStream, Codec>>> {
        let ra = match peer_ri.address(&NTCP2_STYLE) {
            Some(ra) => ra,
            None => match peer_ri.address(&NTCP_STYLE) {
                Some(ra) => ra,
                None => return io_err!(InvalidData, format!("No valid NTCP2 addresses")),
            },
        };

        let addr = ra.addr().unwrap();
        let static_key = self.static_private_key.clone();
        let remote_key = match ra.option(&NTCP2_OPT_S) {
            Some(val) => match I2P_BASE64.decode(val.0.as_bytes()) {
                Ok(key) => key,
                Err(e) => {
                    return io_err!(InvalidData, format!("Invalid static key in address: {}", e))
                }
            },
            None => return io_err!(InvalidData, format!("No static key in address")),
        };

        let aesobfse_key = peer_ri.router_id.hash().0;
        let mut aesobfse_iv = [0; 16];
        match ra.option(&NTCP2_OPT_I) {
            Some(val) => match I2P_BASE64.decode(val.0.as_bytes()) {
                Ok(iv) => aesobfse_iv.copy_from_slice(&iv),
                Err(e) => return io_err!(InvalidData, format!("Invalid IV in address: {}", e)),
            },
            None => return io_err!(InvalidData, format!("No IV in address")),
        }

        let sc_padlen = {
            let mut rng = rand::thread_rng();
            // TODO: Sample padding sizes from an appropriate distribution
            rng.gen_range(0, 16)
        };

        let mut sc_buf = vec![0u8; NTCP2_MTU - 16];
        let sc_len = match frame::gen_session_confirmed((&mut sc_buf, 0), &own_ri, sc_padlen)
            .map(|tup| tup.1)
        {
            Ok(sz) => sz,
            Err(e) => match e {
                GenError::BufferTooSmall(sz) => {
                    return io_err!(
                        InvalidData,
                        format!(
                            "SessionConfirmed message ({}) larger than MTU ({})",
                            sz,
                            NTCP2_MTU - 16
                        )
                    )
                }
                GenError::InvalidOffset
                | GenError::CustomError(_)
                | GenError::NotYetImplemented => return io_err!(InvalidData, "could not generate"),
            },
        };
        sc_buf.truncate(sc_len);
        let sc_len = sc_len + 16;

        // Connect to the peer
        // Return a transport ready for sending and receiving Frames
        // The layer above will convert I2NP packets to Frames
        // (or should the Engine handle timesync packets itself?)
        let transport = Box::new(
            TcpStream::connect(&addr)
                .and_then(move |socket| {
                    // Initialize our initiator NoiseSession using a builder.
                    let builder: Builder = Builder::new(NTCP2_NOISE_PROTOCOL_NAME.parse().unwrap());
                    let mut noise = builder
                        .local_private_key(&static_key)
                        .remote_public_key(&remote_key)
                        .aesobfse(&aesobfse_key, &aesobfse_iv)
                        .enable_ask()
                        .build_initiator()
                        .unwrap();

                    let now = SystemTime::now();
                    let mut ts_a = now.duration_since(UNIX_EPOCH).expect("Time went backwards");
                    ts_a.add_assign(Duration::from_millis(500));
                    let ts_a = ts_a.as_secs() as u32;

                    let mut rng = rand::thread_rng();
                    // TODO: Sample padding sizes from an appropriate distribution
                    let padlen = rng.gen_range(0, 16);

                    // SessionRequest
                    let mut sr_buf = [0u8; SESSION_REQUEST_PT_LEN];
                    match frame::gen_session_request(
                        (&mut sr_buf, 0),
                        2,
                        padlen,
                        sc_len as u16,
                        ts_a,
                    ).map(|tup| tup.1)
                    {
                        Ok(sz) if sz == sr_buf.len() => (),
                        Ok(_) => panic!("Size mismatch"),
                        Err(e) => match e {
                            GenError::BufferTooSmall(_) => panic!("Size mismatch"),
                            GenError::InvalidOffset
                            | GenError::CustomError(_)
                            | GenError::NotYetImplemented => {
                                return io_err!(InvalidData, "could not generate")
                            }
                        },
                    };

                    // -> e, es
                    debug!("C -> e, es");
                    let mut buf = vec![0u8; SESSION_REQUEST_CT_LEN + padlen as usize];
                    noise.write_message(&sr_buf, &mut buf).unwrap();
                    rng.fill(&mut buf[SESSION_REQUEST_CT_LEN..]);
                    noise.set_h_data(2, &buf[SESSION_REQUEST_CT_LEN..]).unwrap();

                    Ok(tokio_io::io::write_all(socket, buf)
                        .and_then(|(conn, _)| {
                            tokio_io::io::read_exact(conn, vec![0u8; SESSION_CREATED_CT_LEN])
                        })
                        .map(move |(c, m)| (c, noise, now, m)))
                })
                .and_then(|f| f)
                .and_then(|(conn, mut noise, rtt_timer, msg)| {
                    // <- e, ee
                    debug!("C <- e, ee");
                    let mut buf = [0u8; SESSION_CREATED_PT_LEN];
                    noise.read_message(&msg, &mut buf).unwrap();

                    // SessionCreated
                    let (padlen, ts_b) = match frame::session_created(&buf) {
                        Err(e) => {
                            return io_err!(Other, format!("SessionCreated parse error: {:?}", e))
                        }
                        Ok((_, (padlen, ts_b))) => (padlen as usize, ts_b),
                    };

                    // Get peer skew
                    let rtt = rtt_timer.elapsed().expect("Time went backwards?");
                    debug!("Peer RTT: {:?}", rtt);

                    Ok(tokio_io::io::read_exact(conn, vec![0u8; padlen])
                        .map(move |(c, m)| (c, noise, m)))
                })
                .and_then(|f| f)
                .and_then(move |(conn, mut noise, padding)| {
                    noise.set_h_data(3, &padding).unwrap();

                    // SessionConfirmed

                    // -> s, se
                    debug!("C -> s, se");
                    let mut buf = vec![0u8; NTCP2_MTU];
                    let len = noise.write_message(&sc_buf, &mut buf).unwrap();
                    buf.truncate(len);
                    Ok(tokio_io::io::write_all(conn, buf).map(|(conn, _)| (conn, noise)))
                })
                .and_then(|f| f)
                .and_then(|(conn, mut noise)| {
                    // Prepare length obfuscation keys and IVs
                    let (ek0, ek1, eiv, dk0, dk1, div) = {
                        let label = String::from("siphash");
                        noise.initialize_ask(vec![label.clone()]).unwrap();
                        let (ask0, ask1) = noise.finalize_ask(&label).unwrap();
                        let mut erdr = io::Cursor::new(&ask0); // Alice to Bob
                        let mut drdr = io::Cursor::new(&ask1); // Bob to Alice

                        (
                            erdr.read_u64::<LittleEndian>().unwrap(),
                            erdr.read_u64::<LittleEndian>().unwrap(),
                            erdr.read_u64::<LittleEndian>().unwrap(),
                            drdr.read_u64::<LittleEndian>().unwrap(),
                            drdr.read_u64::<LittleEndian>().unwrap(),
                            drdr.read_u64::<LittleEndian>().unwrap(),
                        )
                    };

                    // Transition the state machine into transport mode now that the handshake is complete.
                    let noise = noise.into_transport_mode().unwrap();

                    let codec = Codec {
                        noise,
                        noise_buf: [0u8; NTCP2_MTU],
                        enc_len_masker: SipHasher::new_with_keys(ek0, ek1),
                        enc_len_iv: eiv,
                        dec_len_masker: SipHasher::new_with_keys(dk0, dk1),
                        dec_len_iv: div,
                        next_len: None,
                    };

                    Ok(codec.framed(conn))
                }),
        );

        // Add a timeout
        let timed = Deadline::new(transport, Instant::now() + Duration::new(10, 0))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e));

        Ok(Box::new(timed))
    }
}
