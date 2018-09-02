//! A legacy authenticated key agreement protocol over TCP.
//!
//! [NTCP specification](https://geti2p.net/en/docs/transport/ntcp)

use bytes::BytesMut;
use cookie_factory::GenError;
use futures::{sync::mpsc, task, Async, Future, Poll, Sink, Stream};
use nom::{Err, Offset};
use std::io;
use std::iter::repeat;
use std::net::SocketAddr;
use std::time::Duration;
use tokio;
use tokio::net::{TcpListener, TcpStream};
use tokio_codec::{Decoder, Encoder, Framed};
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_timer::Timeout;

use super::{
    session::{EngineTx, SessionContext, SessionEngine, SessionRefs, SessionRx},
    Bid, Handle, Transport,
};
use crypto::{Aes256, SigningPrivateKey};
use data::{Hash, I2PString, RouterAddress, RouterIdentity, RouterInfo};
use i2np::Message;

mod frame;
mod handshake;

lazy_static! {
    pub(super) static ref NTCP_STYLE: I2PString = I2PString::new("NTCP");
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
// Session handling
//

struct Session<T, C>
where
    T: AsyncRead + AsyncWrite,
    C: Decoder<Item = Frame, Error = io::Error>,
    C: Encoder<Item = Frame, Error = io::Error>,
{
    _ctx: SessionContext<Frame>,
    ri: RouterIdentity,
    upstream: Framed<T, C>,
    engine: EngineTx<Frame>,
    outbound: SessionRx<Frame>,
}

impl<T, C> Session<T, C>
where
    T: AsyncRead + AsyncWrite,
    C: Decoder<Item = Frame, Error = io::Error>,
    C: Encoder<Item = Frame, Error = io::Error>,
{
    fn new(ri: RouterIdentity, upstream: Framed<T, C>, session_refs: SessionRefs<Frame>) -> Self {
        let (tx, rx) = mpsc::unbounded();
        Session {
            _ctx: SessionContext::new(ri.hash(), session_refs.state, tx),
            ri: ri,
            upstream,
            engine: session_refs.engine,
            outbound: rx,
        }
    }
}

impl<T, C> Future for Session<T, C>
where
    T: AsyncRead + AsyncWrite,
    C: Decoder<Item = Frame, Error = io::Error>,
    C: Encoder<Item = Frame, Error = io::Error>,
{
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<(), io::Error> {
        // Write frames
        const FRAMES_PER_TICK: usize = 10;
        for i in 0..FRAMES_PER_TICK {
            match self.outbound.poll().unwrap() {
                Async::Ready(Some(f)) => {
                    self.upstream.start_send(f)?;

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

        // Flush frames
        self.upstream.poll_complete()?;

        // Read frames
        while let Async::Ready(f) = self.upstream.poll()? {
            if let Some(frame) = f {
                self.engine.unbounded_send((self.ri.hash(), frame)).unwrap();
            } else {
                // EOF was reached. The remote peer has disconnected.
                return Ok(Async::Ready(()));
            }
        }

        // We know we got a `NotReady` from either `self.outbound` or `self.upstream`,
        // so the contract is respected.
        Ok(Async::NotReady)
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

    pub fn handle(&self) -> Handle {
        self.session_engine.handle()
    }

    pub fn address(&self) -> RouterAddress {
        RouterAddress::new(&NTCP_STYLE, self.addr)
    }

    pub fn listen(
        &self,
        own_ri: RouterIdentity,
        own_key: SigningPrivateKey,
    ) -> impl Future<Item = (), Error = io::Error> {
        // Bind to the address
        let listener = TcpListener::bind(&self.addr).unwrap();

        // Give each incoming connection the references it needs
        let session_refs = self.session_engine.refs();
        let conns = listener.incoming().zip(session_refs);

        // For each incoming connection:
        conns.for_each(move |(conn, session_refs)| {
            info!("Incoming connection!");
            // Execute the handshake
            let conn = handshake::IBHandshake::new(conn, own_ri.clone(), own_key.clone());

            // Once connected:
            let process_conn = conn.and_then(|(ri, conn)| Session::new(ri, conn, session_refs));

            tokio::spawn(process_conn.map_err(|_| ()));

            Ok(())
        })
    }

    pub fn connect(
        &self,
        own_ri: RouterIdentity,
        own_key: SigningPrivateKey,
        peer_ri: RouterInfo,
    ) -> impl Future<Item = (), Error = io::Error> {
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
        let timed = Timeout::new(conn, Duration::new(10, 0))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e));

        // Once connected:
        let session_refs = self.session_engine.refs();
        timed.and_then(|(ri, conn)| {
            let session = Session::new(ri, conn, session_refs);
            tokio::spawn(session.map_err(|_| ()));
            Ok(())
        })
    }
}

impl Transport for Engine {
    fn bid(&self, hash: &Hash, msg_size: usize) -> Option<Bid> {
        if msg_size > NTCP_MTU {
            return None;
        }

        Some(Bid {
            bid: if self.session_engine.have_session(hash) {
                25
            } else {
                70
            },
            handle: self.session_engine.handle(),
        })
    }
}

impl Stream for Engine {
    type Item = (Hash, Message);
    type Error = ();

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        while let Async::Ready(f) = self
            .session_engine
            .poll(|msg| Frame::Standard(msg), |ts| Frame::TimeSync(ts))?
        {
            match f {
                Some((from, Frame::Standard(msg))) => return Ok(Some((from, msg)).into()),
                Some((from, frame)) => {
                    // TODO: Do something
                    debug!("Received frame from {}: {:?}", from, frame);
                }
                None => return Ok(Async::Ready(None)),
            }
        }
        Ok(Async::NotReady)
    }
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;
    use cookie_factory::GenError;
    use futures::{lazy, Async, Future};
    use nom::{Err, Offset};
    use std::io::{self, Read, Write};
    use std::iter::repeat;
    use tokio_codec::{Decoder, Encoder};

    use super::{frame, Frame, Session, SessionEngine, NTCP_MTU};
    use data::RouterSecretKeys;
    use i2np::Message;
    use transport::tests::{AliceNet, BobNet, NetworkCable};

    struct TestCodec;

    impl Decoder for TestCodec {
        type Item = Frame;
        type Error = io::Error;

        fn decode(&mut self, buf: &mut BytesMut) -> io::Result<Option<Frame>> {
            // Parse a frame
            let (consumed, f) = match frame::frame(buf) {
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

            Ok(Some(f))
        }
    }

    impl Encoder for TestCodec {
        type Item = Frame;
        type Error = io::Error;

        fn encode(&mut self, frame: Frame, buf: &mut BytesMut) -> io::Result<()> {
            let start = buf.len();
            buf.extend(repeat(0).take(NTCP_MTU));

            match frame::gen_frame((buf, start), &frame).map(|tup| tup.1) {
                Ok(sz) => {
                    buf.truncate(sz);
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

    lazy_static! {
        static ref DUMMY_MSG: Message = Message::dummy_data();
    }

    const DUMMY_MSG_NTCP_DATA: &'static [u8] = &[
        0x00, 0x1e, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x23, 0x45, 0x67, 0x87, 0xc0,
        0x00, 0x0e, 0x2c, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x53,
        0xb8, 0x02, 0xbb,
    ];

    #[test]
    fn session_send() {
        let rid = RouterSecretKeys::new().rid;
        let hash = rid.hash();

        let cable = NetworkCable::new();
        let alice_net = AliceNet::new(cable.clone());
        let alice_framed = TestCodec {}.framed(alice_net);

        let mut engine = SessionEngine::new();
        let mut session = Session::new(rid, alice_framed, engine.refs());

        // Run on a task context
        lazy(move || {
            let handle = engine.handle();
            handle.send(hash.clone(), Message::dummy_data()).unwrap();

            // Check it has not yet been received
            let mut bob_net = BobNet::new(cable);
            let mut received = Vec::new();
            assert!(bob_net.read_to_end(&mut received).is_err());
            assert!(received.is_empty());

            // Pass it through the engine, still not received
            engine
                .poll(|msg| Frame::Standard(msg), |_| panic!())
                .unwrap();
            received.clear();
            assert!(bob_net.read_to_end(&mut received).is_err());
            assert!(received.is_empty());

            // Pass it through the session, now it's on the wire
            session.poll().unwrap();
            received.clear();
            assert!(bob_net.read_to_end(&mut received).is_err());
            assert_eq!(&received, &DUMMY_MSG_NTCP_DATA);

            Ok::<(), ()>(())
        }).wait()
            .unwrap();
    }

    #[test]
    fn session_receive() {
        let rid = RouterSecretKeys::new().rid;
        let hash = rid.hash();

        let cable = NetworkCable::new();
        let bob_net = BobNet::new(cable.clone());
        let bob_framed = TestCodec {}.framed(bob_net);

        let mut engine = SessionEngine::new();
        let mut session = Session::new(rid, bob_framed, engine.refs());

        // Run on a task context
        lazy(move || {
            let mut alice_net = AliceNet::new(cable);
            assert!(alice_net.write_all(DUMMY_MSG_NTCP_DATA).is_ok());

            // Check it has not yet been received
            engine.poll(|_| panic!(), |_| panic!()).unwrap();

            // Pass it through the session
            session.poll().unwrap();

            // The engine should receive it now
            match engine.poll(|_| panic!(), |_| panic!()).unwrap() {
                Async::Ready(Some((h, frame))) => {
                    assert_eq!(h, hash);
                    match frame {
                        Frame::Standard(msg) => {
                            assert_eq!(msg, *DUMMY_MSG);
                        }
                        _ => panic!(),
                    }
                }
                _ => panic!(),
            }

            Ok::<(), ()>(())
        }).wait()
            .unwrap();
    }
}
