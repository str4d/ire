use bytes::BytesMut;
use cookie_factory::GenError;
use futures::{Future, Stream};
use nom::{Err, Offset};
use std::io;
use std::iter::repeat;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio;
use tokio::net::{TcpListener, TcpStream};
use tokio_io::codec::{Decoder, Encoder, Framed};
use tokio_io::IoFuture;
use tokio_timer::Deadline;

use crypto::{Aes256, SigningPrivateKey};
use data::{I2PString, RouterIdentity, RouterInfo};
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
            None => return Ok(None),
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

pub struct Engine;

impl Engine {
    pub fn new() -> Self {
        Engine
    }

    pub fn listen(
        &self,
        own_ri: RouterIdentity,
        own_key: SigningPrivateKey,
        addr: &SocketAddr,
    ) -> IoFuture<()> {
        // Bind to the address
        let listener = TcpListener::bind(addr).unwrap();

        // For each incoming connection:
        Box::new(listener.incoming().for_each(move |conn| {
            info!("Incoming connection!");
            // Execute the handshake
            let conn = handshake::HandshakeTransport::<
                TcpStream,
                handshake::InboundHandshakeCodec,
                handshake::IBHandshakeState,
            >::listen(conn, own_ri.clone(), own_key.clone());

            // Once connected:
            let process_conn = conn.and_then(|conn| {
                info!("Connection established!");
                // For every message received:
                conn.for_each(|frame| {
                    debug!("Received frame: {:?}", frame);
                    // TODO: Do something
                    Ok(())
                })
            });

            tokio::spawn(process_conn.map_err(|_| ()));

            Ok(())
        }))
    }

    pub fn connect(
        &self,
        own_ri: RouterIdentity,
        own_key: SigningPrivateKey,
        peer_ri: RouterInfo,
    ) -> IoFuture<Framed<TcpStream, Codec>> {
        // TODO return error if there are no valid NTCP addresses (for some reason)
        let addr = peer_ri.address(&NTCP_STYLE).unwrap().addr().unwrap();

        // Connect to the peer
        // Return a transport ready for sending and receiving Frames
        // The layer above will convert I2NP packets to Frames
        // (or should the Engine handle timesync packets itself?)
        let transport = Box::new(TcpStream::connect(&addr).and_then(|socket| {
            handshake::HandshakeTransport::<
                TcpStream,
                handshake::OutboundHandshakeCodec,
                handshake::OBHandshakeState,
            >::connect(socket, own_ri, own_key, peer_ri.router_id)
        }));

        // Add a timeout
        Box::new(
            Deadline::new(transport, Instant::now() + Duration::new(10, 0))
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e)),
        )
    }
}
