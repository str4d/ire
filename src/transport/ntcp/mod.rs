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
use std::iter::repeat;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::{
    codec::{Decoder, Encoder, Framed},
    io::{self, AsyncRead, AsyncWrite},
    net::tcp::{TcpListener, TcpStream},
    spawn,
    timer::Timeout,
};

use super::{
    session::{self, SessionContext, SessionManager, SessionRefs, SessionRx},
    Bid, Transport,
};
use crate::crypto::{Aes256, SigningPrivateKey};
use crate::data::{Hash, I2PString, RouterAddress, RouterIdentity, RouterInfo};
use crate::i2np::Message;
use crate::router::{
    types::{Distributor, DistributorResult},
    Context,
};

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

#[cfg_attr(tarpaulin, skip)]
impl fmt::Debug for Frame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Frame::Standard(ref msg) => write!(f, "I2NP message:\n{}", msg),
            Frame::TimeSync(ts) => write!(f, "Timesync ({})", ts),
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
                ));
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

struct Session<T, C, D>
where
    T: AsyncRead + AsyncWrite,
    C: Decoder<Item = Frame, Error = io::Error>,
    C: Encoder<Item = Frame, Error = io::Error>,
    D: Distributor,
{
    ib: InboundSession<T, C>,
    ob: OutboundSession<T, C>,
    distributor: D,
    pending_ib: Option<DistributorResult>,
    outbound: SessionRx<Frame>,
    cached_ob_frame: Option<Frame>,
}

impl<T, C, D> Session<T, C, D>
where
    T: AsyncRead + AsyncWrite,
    C: Decoder<Item = Frame, Error = io::Error>,
    C: Encoder<Item = Frame, Error = io::Error>,
    D: Distributor,
{
    fn new(
        ri: RouterIdentity,
        upstream: Framed<T, C>,
        session_refs: SessionRefs<Frame, D>,
    ) -> Self {
        let (downstream, upstream) = upstream.split();
        let (tx, rx) = mpsc::unbounded();
        let ctx = SessionContext::new(ri.hash(), session_refs.state, tx);
        Session {
            ib: InboundSession::new(ctx, upstream),
            ob: OutboundSession::new(downstream),
            distributor: session_refs.distributor,
            pending_ib: None,
            outbound: rx,
            cached_ob_frame: None,
        }
    }
}

impl<T, C, D> Future for Session<T, C, D>
where
    T: AsyncRead + AsyncWrite,
    C: Decoder<Item = Frame, Error = io::Error>,
    C: Encoder<Item = Frame, Error = io::Error>,
    D: Distributor,
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
        loop {
            if let Some(f) = &mut self.pending_ib {
                try_ready!(f
                    .poll()
                    .map_err(|_| io::Error::new(io::ErrorKind::Other, "A subsystem is down!")));
                self.pending_ib = None;
            }

            let f = try_ready!(self.ib.poll());
            if let Some((from, msg)) = f {
                self.pending_ib = Some(self.distributor.handle(from, msg));
            } else {
                // EOF was reached. The remote peer has disconnected.
                return Ok(Async::Ready(()));
            }
        }
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
    type Item = (Hash, Message);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, io::Error> {
        loop {
            match try_ready!(self.upstream.poll()) {
                Some(frame) => match frame {
                    Frame::Standard(msg) => {
                        return Ok(Async::Ready(Some((self.ctx.hash.clone(), msg))));
                    }
                    frame => {
                        // TODO: Do something
                        debug!(
                            "Dropping unhandled frame from {}: {:?}",
                            self.ctx.hash, frame
                        );
                    }
                },
                None => {
                    // EOF was reached. The remote peer has disconnected.
                    return Ok(Async::Ready(None));
                }
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

pub struct Manager<D: Distributor> {
    addr: SocketAddr,
    session_manager: SessionManager<Frame, D>,
    ctx: Option<Arc<Context>>,
}

impl<D: Distributor> Manager<D> {
    pub fn new(addr: SocketAddr, distributor: D) -> Self {
        Manager {
            addr,
            session_manager: session::new_manager(distributor),
            ctx: None,
        }
    }

    pub fn set_context(&mut self, ctx: Arc<Context>) {
        self.ctx = Some(ctx);
    }

    pub fn sink(&self) -> OutboundSink<D> {
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

fn connect<D: Distributor>(
    own_ri: RouterIdentity,
    own_key: SigningPrivateKey,
    peer_ri: RouterInfo,
    session_refs: SessionRefs<Frame, D>,
) -> io::Result<impl Future<Item = (), Error = io::Error>> {
    let addr = match peer_ri.address(&NTCP_STYLE, |_| true) {
        Some(ra) => ra.addr().unwrap(),
        None => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "No valid NTCP addresses",
            ));
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

impl<D: Distributor> Transport for Manager<D> {
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

pub struct OutboundSink<D: Distributor> {
    ctx: Arc<Context>,
    session_refs: SessionRefs<Frame, D>,
}

impl<D: Distributor> Sink for OutboundSink<D> {
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
                    Ok(f) => {
                        spawn(f.map_err(|e| {
                            error!("Error while connecting: {}", e);
                        }));
                    }
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
    use futures::{lazy, Future, Sink};
    use nom::{Err, Offset};
    use std::iter::repeat;
    use tokio::{
        codec::{Decoder, Encoder},
        io::{self, Read, Write},
    };

    use super::{frame, Frame, Manager, Session, NTCP_MTU};
    use crate::i2np::Message;
    use crate::router::mock::{mock_context, MockDistributor};
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
                    ));
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

        let distributor = MockDistributor::new();
        let mut manager = Manager::new("127.0.0.1:1234".parse().unwrap(), distributor);
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

        let distributor = MockDistributor::new();
        let received = distributor.received.clone();
        let manager = Manager::new("127.0.0.1:1234".parse().unwrap(), distributor);
        let mut session = Session::new(rid, bob_framed, manager.session_manager.refs());

        // Run on a task context
        lazy(move || {
            let mut alice_net = AliceNet::new(cable);
            assert!(alice_net.write_all(DUMMY_MSG_NTCP_DATA).is_ok());

            // Check it has not yet been received
            assert!(received.lock().unwrap().is_empty());

            // Pass it through the session
            session.poll().unwrap();

            // The distributor should have received it now
            let r = received.lock().unwrap();
            assert_eq!(r.len(), 1);
            assert_eq!(r[0].0, hash);
            assert_eq!(r[0].1, *DUMMY_MSG);

            Ok::<(), ()>(())
        })
        .wait()
        .unwrap();
    }
}
