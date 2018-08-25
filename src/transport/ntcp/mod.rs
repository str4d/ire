//! A legacy authenticated key agreement protocol over TCP.
//!
//! [NTCP specification](https://geti2p.net/en/docs/transport/ntcp)

use bytes::BytesMut;
use cookie_factory::GenError;
use futures::{Future, Poll, Stream};
use nom::{Err, Offset};
use std::io;
use std::iter::repeat;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio;
use tokio::net::{TcpListener, TcpStream};
use tokio_codec::{Decoder, Encoder};
use tokio_io::IoFuture;
use tokio_timer::Deadline;

use super::session::{EngineHandle, Session, SessionEngine};
use crypto::{Aes256, SigningPrivateKey};
use data::{I2PString, RouterAddress, RouterIdentity, RouterInfo};
use i2np::Message;

mod frame;
mod handshake;

lazy_static! {
    pub static ref NTCP_STYLE: I2PString = I2PString::new("NTCP");
}

// Max NTCP message size is 16kB
const NTCP_MTU: usize = 16384;

//
// Message transport
//

pub enum Frame {
    Standard(Message),
    TimeSync(u32),
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

impl Decoder for Codec {
    type Item = Frame;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> io::Result<Option<Frame>> {
        // Encrypt message in-place
        match self.aes.decrypt_blocks(&mut buf[self.decrypted..]) {
            Some(end) => self.decrypted += end,
            None => if self.decrypted == 0 {
                return Ok(None);
            },
        };

        // Parse a frame
        let (consumed, f) = match frame::frame(&buf[0..self.decrypted]) {
            Err(Err::Incomplete(_)) => return Ok(None),
            Err(Err::Error(e)) | Err(Err::Failure(e)) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("parse error: {:?}", e),
                ))
            }
            Ok((i, frame)) => (buf.offset(i), frame),
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
// Connection management engine
//

pub struct Engine {
    addr: SocketAddr,
    session_engine: SessionEngine<Frame>,
}

impl Engine {
    pub fn new(addr: SocketAddr) -> Self {
        Engine {
            addr,
            session_engine: SessionEngine::new(),
        }
    }

    pub fn handle(&self) -> EngineHandle<Frame> {
        self.session_engine.handle()
    }

    pub fn address(&self) -> RouterAddress {
        RouterAddress::new(&NTCP_STYLE, self.addr)
    }

    pub fn listen(&self, own_ri: RouterIdentity, own_key: SigningPrivateKey) -> IoFuture<()> {
        // Bind to the address
        let listener = TcpListener::bind(&self.addr).unwrap();

        // Give each incoming connection the references it needs
        let session_refs = self.session_engine.refs();
        let conns = listener.incoming().zip(session_refs);

        // For each incoming connection:
        Box::new(conns.for_each(move |(conn, session_refs)| {
            info!("Incoming connection!");
            // Execute the handshake
            let conn = handshake::IBHandshake::new(conn, own_ri.clone(), own_key.clone());

            // Once connected:
            let process_conn = conn.and_then(|(ri, conn)| Session::new(ri, conn, session_refs));

            tokio::spawn(process_conn.map_err(|_| ()));

            Ok(())
        }))
    }

    pub fn connect(
        &self,
        own_ri: RouterIdentity,
        own_key: SigningPrivateKey,
        peer_ri: RouterInfo,
    ) -> IoFuture<()> {
        // TODO return error if there are no valid NTCP addresses (for some reason)
        let addr = peer_ri
            .address(&NTCP_STYLE, |_| true)
            .unwrap()
            .addr()
            .unwrap();

        // Connect to the peer
        let conn = TcpStream::connect(&addr).and_then(|socket| {
            handshake::OBHandshake::new(socket, own_ri, own_key, peer_ri.router_id)
        });

        // Add a timeout
        let timed = Deadline::new(conn, Instant::now() + Duration::new(10, 0))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e));

        // Once connected:
        let session_refs = self.session_engine.refs();
        Box::new(timed.and_then(|(ri, conn)| {
            let session = Session::new(ri, conn, session_refs);
            tokio::spawn(session.map_err(|_| ()));
            Ok(())
        }))
    }
}

impl Future for Engine {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<(), ()> {
        self.session_engine.poll()
    }
}
