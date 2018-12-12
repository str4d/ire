//! A legacy authenticated key agreement protocol over TCP.
//!
//! [NTCP specification](https://geti2p.net/en/docs/transport/ntcp)

use bytes::BytesMut;
use cookie_factory::GenError;
use futures::{
    stream::{SplitSink, SplitStream},
    sync::mpsc,
    try_ready, Async, AsyncSink, Future, Poll, Sink, StartSend, Stream,
};
use nom::{Err, Offset};
use std::io;
use std::iter::repeat;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio_codec::{Decoder, Encoder, Framed};
use tokio_executor::spawn;
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_tcp::{TcpListener, TcpStream};
use tokio_timer::Timeout;

use super::{
    session::{self, EngineRx, EngineTx, SessionContext, SessionManager, SessionRefs, SessionRx},
    Bid, Transport,
};
use crate::crypto::{Aes256, SigningPrivateKey};
use crate::data::{Hash, I2PString, RouterAddress, RouterIdentity, RouterInfo};
use crate::i2np::Message;
use crate::router::Context;

#[allow(needless_pass_by_value)]
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
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Frame::Standard(_) => "Standard message".fmt(formatter),
            Frame::TimeSync(ts) => format!("Timesync ({})", ts).fmt(formatter),
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
            None => {
                if self.decrypted == 0 {
                    return Ok(None);
                }
            }
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
    ib: InboundSession<T, C>,
    ob: OutboundSession<T, C>,
    engine: EngineTx<Frame>,
    outbound: SessionRx<Frame>,
    cached_ob_frame: Option<Frame>,
}

impl<T, C> Session<T, C>
where
    T: AsyncRead + AsyncWrite,
    C: Decoder<Item = Frame, Error = io::Error>,
    C: Encoder<Item = Frame, Error = io::Error>,
{
    fn new(ri: RouterIdentity, upstream: Framed<T, C>, session_refs: SessionRefs<Frame>) -> Self {
        let (downstream, upstream) = upstream.split();
        let (tx, rx) = mpsc::unbounded();
        let ctx = SessionContext::new(ri.hash(), session_refs.state, tx);
        Session {
            ib: InboundSession::new(ctx, upstream),
            ob: OutboundSession::new(downstream),
            engine: session_refs.engine,
            outbound: rx,
            cached_ob_frame: None,
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
        // Write cached frame, if any
        let mut write_ready = true;
        if let Some(frame) = self.cached_ob_frame.take() {
            match self.ob.start_send(frame)? {
                AsyncSink::Ready => (),
                AsyncSink::NotReady(frame) => {
                    self.cached_ob_frame = Some(frame);
                    write_ready = false;
                }
            }
        }

        // Write frames
        while write_ready {
            match self.outbound.poll().unwrap() {
                Async::Ready(Some(frame)) => match self.ob.start_send(frame)? {
                    AsyncSink::Ready => (),
                    AsyncSink::NotReady(frame) => {
                        self.cached_ob_frame = Some(frame);
                        write_ready = false;
                    }
                },
                _ => break,
            }
        }

        // Flush frames
        self.ob.poll_complete()?;

        // Read frames
        while let Async::Ready(f) = self.ib.poll()? {
            if let Some((hash, frame)) = f {
                self.engine.unbounded_send((hash, frame)).unwrap();
            } else {
                // EOF was reached. The remote peer has disconnected.
                return Ok(Async::Ready(()));
            }
        }

        // We know we got a `NotReady` from either `self.ob` or `self.ib`,
        // so the contract is respected.
        Ok(Async::NotReady)
    }
}

struct InboundSession<T, C>
where
    T: AsyncRead + AsyncWrite,
    C: Decoder<Item = Frame, Error = io::Error>,
    C: Encoder<Item = Frame, Error = io::Error>,
{
    ctx: SessionContext<Frame>,
    upstream: SplitStream<Framed<T, C>>,
}

impl<T, C> InboundSession<T, C>
where
    T: AsyncRead + AsyncWrite,
    C: Decoder<Item = Frame, Error = io::Error>,
    C: Encoder<Item = Frame, Error = io::Error>,
{
    fn new(ctx: SessionContext<Frame>, upstream: SplitStream<Framed<T, C>>) -> Self {
        InboundSession { ctx, upstream }
    }
}

impl<T, C> Stream for InboundSession<T, C>
where
    T: AsyncRead + AsyncWrite,
    C: Decoder<Item = Frame, Error = io::Error>,
    C: Encoder<Item = Frame, Error = io::Error>,
{
    type Item = (Hash, Frame);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, io::Error> {
        match try_ready!(self.upstream.poll()) {
            Some(frame) => Ok(Async::Ready(Some((self.ctx.hash.clone(), frame)))),
            None => {
                // EOF was reached. The remote peer has disconnected.
                Ok(Async::Ready(None))
            }
        }
    }
}

struct OutboundSession<T, C>
where
    T: AsyncRead + AsyncWrite,
    C: Decoder<Item = Frame, Error = io::Error>,
    C: Encoder<Item = Frame, Error = io::Error>,
{
    downstream: SplitSink<Framed<T, C>>,
}

impl<T, C> OutboundSession<T, C>
where
    T: AsyncRead + AsyncWrite,
    C: Decoder<Item = Frame, Error = io::Error>,
    C: Encoder<Item = Frame, Error = io::Error>,
{
    fn new(downstream: SplitSink<Framed<T, C>>) -> Self {
        OutboundSession { downstream }
    }
}

impl<T, C> Sink for OutboundSession<T, C>
where
    T: AsyncRead + AsyncWrite,
    C: Decoder<Item = Frame, Error = io::Error>,
    C: Encoder<Item = Frame, Error = io::Error>,
{
    type SinkItem = Frame;
    type SinkError = io::Error;

    fn start_send(&mut self, frame: Frame) -> StartSend<Frame, io::Error> {
        self.downstream.start_send(frame)
    }

    fn poll_complete(&mut self) -> Poll<(), io::Error> {
        self.downstream.poll_complete()
    }
}

//
// Connection management engine
//

pub struct Manager {
    addr: SocketAddr,
    session_manager: SessionManager<Frame>,
    ctx: Option<Arc<Context>>,
}

pub struct Engine {
    inbound: EngineRx<Frame>,
}

impl Manager {
    pub fn new(addr: SocketAddr) -> (Self, Engine) {
        let (session_manager, inbound) = session::new_manager();
        (
            Manager {
                addr,
                session_manager,
                ctx: None,
            },
            Engine { inbound },
        )
    }

    pub fn set_context(&mut self, ctx: Arc<Context>) {
        self.ctx = Some(ctx);
    }

    pub fn sink(&self) -> OutboundSink {
        let ctx = self
            .ctx
            .as_ref()
            .cloned()
            .expect("Should have called set_context()");
        OutboundSink {
            ctx,
            session_refs: self.session_manager.refs(),
        }
    }

    pub fn address(&self) -> RouterAddress {
        RouterAddress::new(&NTCP_STYLE, self.addr)
    }

    pub fn listen(
        &self,
        own_ri: RouterIdentity,
        own_key: SigningPrivateKey,
    ) -> impl Future<Item = (), Error = io::Error> {
        info!("Listening on {}", self.addr);

        // Bind to the address
        let listener = TcpListener::bind(&self.addr).unwrap();

        // Give each incoming connection the references it needs
        let session_refs = self.session_manager.refs();
        let conns = listener.incoming().zip(session_refs);

        // For each incoming connection:
        conns.for_each(move |(conn, session_refs)| {
            info!("Incoming connection!");
            // Execute the handshake
            let conn = handshake::IBHandshake::new(conn, own_ri.clone(), own_key.clone());

            // Once connected:
            let process_conn = conn.and_then(|(ri, conn)| Session::new(ri, conn, session_refs));

            spawn(process_conn.map_err(|_| ()));

            Ok(())
        })
    }

    pub fn connect(
        &self,
        own_ri: RouterIdentity,
        own_key: SigningPrivateKey,
        peer_ri: RouterInfo,
    ) -> io::Result<impl Future<Item = (), Error = io::Error>> {
        connect(own_ri, own_key, peer_ri, self.session_manager.refs())
    }
}

fn connect(
    own_ri: RouterIdentity,
    own_key: SigningPrivateKey,
    peer_ri: RouterInfo,
    session_refs: SessionRefs<Frame>,
) -> io::Result<impl Future<Item = (), Error = io::Error>> {
    let addr = match peer_ri.address(&NTCP_STYLE, |_| true) {
        Some(ra) => ra.addr().unwrap(),
        None => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "No valid NTCP addresses",
            ))
        }
    };

    // Connect to the peer
    let conn = TcpStream::connect(&addr)
        .and_then(|socket| handshake::OBHandshake::new(socket, own_ri, own_key, peer_ri.router_id));

    // Add a timeout
    let timed = Timeout::new(conn, Duration::new(10, 0))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e));

    // Once connected:
    Ok(timed.and_then(|(ri, conn)| {
        let session = Session::new(ri, conn, session_refs);
        spawn(session.map_err(|_| ()));
        Ok(())
    }))
}

impl Transport for Manager {
    fn is_established(&self, hash: &Hash) -> bool {
        self.session_manager.have_session(hash)
    }

    fn bid(&self, peer: &RouterInfo, msg_size: usize) -> Option<Bid> {
        if msg_size > NTCP_MTU {
            return None;
        }

        if peer.address(&NTCP_STYLE, |_| true).is_none() {
            return None;
        }

        Some(Bid {
            bid: if self.is_established(&peer.router_id.hash()) {
                25
            } else {
                70
            },
            sink: Box::new(self.sink()),
        })
    }
}

impl Stream for Engine {
    type Item = (Hash, Message);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        while let Async::Ready(f) = self.inbound.poll().unwrap() {
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

pub struct OutboundSink {
    ctx: Arc<Context>,
    session_refs: SessionRefs<Frame>,
}

impl Sink for OutboundSink {
    type SinkItem = (RouterInfo, Message);
    type SinkError = io::Error;

    fn start_send(
        &mut self,
        (peer, msg): Self::SinkItem,
    ) -> StartSend<Self::SinkItem, Self::SinkError> {
        let session_refs = self.session_refs.clone();

        match self
            .session_refs
            .state
            .send(&peer.router_id.hash(), Frame::Standard(msg), || {
                // Connect to the peer
                let own_rid = self.ctx.keys.rid.clone();
                let own_key = self.ctx.keys.signing_private_key.clone();
                let peer = peer.clone();
                let session_refs = session_refs.clone();
                match connect(own_rid, own_key, peer, session_refs) {
                    Ok(f) => spawn(f.map_err(|e| {
                        error!("Error while connecting: {}", e);
                    })),
                    Err(e) => error!("{}", e),
                }
            }) {
            Ok(AsyncSink::Ready) => Ok(AsyncSink::Ready),
            Ok(AsyncSink::NotReady(Frame::Standard(msg))) => Ok(AsyncSink::NotReady((peer, msg))),
            Err(e) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                format!("Channel to session is broken: {}", e),
            )),
            _ => unreachable!(),
        }
    }

    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        // Channels always complete immediately
        Ok(Async::Ready(()))
    }
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;
    use cookie_factory::GenError;
    use futures::{lazy, Async, Future, Sink, Stream};
    use nom::{Err, Offset};
    use std::io::{self, Read, Write};
    use std::iter::repeat;
    use tokio_codec::{Decoder, Encoder};

    use super::{frame, Frame, Manager, Session, NTCP_MTU};
    use crate::i2np::Message;
    use crate::router::mock::mock_context;
    use crate::transport::tests::{AliceNet, BobNet, NetworkCable};

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

    const DUMMY_MSG_NTCP_DATA: &[u8] = &[
        0x00, 0x1e, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x23, 0x45, 0x67, 0x87, 0xc0,
        0x00, 0x0e, 0x2c, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x53,
        0xb8, 0x02, 0xbb,
    ];

    #[test]
    fn session_send() {
        let ctx = mock_context();
        let ri = ctx.ri.read().unwrap().clone();
        let rid = ctx.keys.rid.clone();

        let cable = NetworkCable::new();
        let alice_net = AliceNet::new(cable.clone());
        let alice_framed = TestCodec {}.framed(alice_net);

        let (mut manager, _) = Manager::new("127.0.0.1:1234".parse().unwrap());
        manager.set_context(ctx);

        // Run on a task context
        lazy(move || {
            // Send a message, session is requested, message queued
            let sink = manager.sink();
            sink.send((ri.clone(), Message::dummy_data()))
                .poll()
                .unwrap();

            // Check it has not yet been received
            let mut bob_net = BobNet::new(cable);
            let mut received = Vec::new();
            assert!(bob_net.read_to_end(&mut received).is_err());
            assert!(received.is_empty());

            // Create a session
            let mut session = Session::new(rid, alice_framed, manager.session_manager.refs());

            // Pass it through the session, now it's on the wire
            session.poll().unwrap();
            received.clear();
            assert!(bob_net.read_to_end(&mut received).is_err());
            assert_eq!(&received, &DUMMY_MSG_NTCP_DATA);

            Ok::<(), ()>(())
        })
        .wait()
        .unwrap();
    }

    #[test]
    fn session_receive() {
        let ctx = mock_context();
        let rid = ctx.keys.rid.clone();
        let hash = rid.hash();

        let cable = NetworkCable::new();
        let bob_net = BobNet::new(cable.clone());
        let bob_framed = TestCodec {}.framed(bob_net);

        let (manager, mut engine) = Manager::new("127.0.0.1:1234".parse().unwrap());
        let mut session = Session::new(rid, bob_framed, manager.session_manager.refs());

        // Run on a task context
        lazy(move || {
            let mut alice_net = AliceNet::new(cable);
            assert!(alice_net.write_all(DUMMY_MSG_NTCP_DATA).is_ok());

            // Check it has not yet been received
            match engine.poll().unwrap() {
                Async::NotReady => (),
                _ => panic!(),
            };

            // Pass it through the session
            session.poll().unwrap();

            // The engine should receive it now
            match engine.poll().unwrap() {
                Async::Ready(Some((h, msg))) => {
                    assert_eq!(h, hash);
                    assert_eq!(msg, *DUMMY_MSG);
                }
                _ => panic!(),
            }

            Ok::<(), ()>(())
        })
        .wait()
        .unwrap();
    }
}
