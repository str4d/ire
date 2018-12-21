//! An authenticated key agreement protocol over TCP, based on the Noise
//! protocol framework.
//!
//! The Noise protocol name is `Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256`.
//! NTCP2 defines three extensions to `Noise_XK_25519_ChaChaPoly_SHA256`, which
//! generally follow the guidelines in section 13 of the Noise specification:
//!
//! 1. Cleartext ephemeral keys are obfuscated with AES-CBC encryption using a
//!    pre-shared (by publication in the responder's RouterInfo) key and IV.
//!    This is indicated by the `aesobfse` modifier.
//!
//! 2. Random cleartext padding is appended to messages 1 and 2 (which are both
//!    fixed-length). The cleartext padding is authenticated by calling MixHash
//!    at the beginning of the token patterns for messages 2 and 3; this is
//!    indicated by the `hs2+hs3` modifiers.
//!
//!    - Random padding is added to message 3 and data-phase messages inside
//!      the AEAD ciphertexts, requiring no changes to the handshake protocol.
//!      The length of message 3 is sent inside message 1.
//!
//! 3. A two-byte frame length field is prepended to each data-phase message.
//!    To avoid transmitting identifiable length fields in stream, the frame
//!    length is obfuscated by XORing a mask derived from SipHash-2-4, using
//!    Additional Symmetric Keys derived from the final Noise chaining key. As
//!    this occurs after the handshake is completed, it has no modifier in the
//!    protocol name.
//!
//! [NTCP2 specification](https://geti2p.net/spec/ntcp2)

use bytes::BytesMut;
use cookie_factory::GenError;
use futures::{
    stream::{SplitSink, SplitStream},
    sync::mpsc,
    try_ready, Async, AsyncSink, Future, Poll, Sink, StartSend, Stream,
};
use i2p_snow::{self, Builder};
use nom::Err;
use rand::{rngs::OsRng, Rng};
use siphasher::sip::SipHasher;
use std::collections::VecDeque;
use std::fmt;
use std::fs::File;
use std::hash::Hasher;
use std::io::{self, Read, Write};
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
    ntcp::NTCP_STYLE,
    session::{self, SessionContext, SessionManager, SessionRefs, SessionRx},
    Bid, Transport,
};
use crate::constants::I2P_BASE64;
use crate::data::{Hash, I2PString, RouterAddress, RouterIdentity, RouterInfo};
use crate::i2np::{DatabaseStore, Message, MessagePayload};
use crate::router::{
    types::{Distributor, DistributorResult},
    Context,
};

#[allow(needless_pass_by_value)]
mod frame;

mod handshake;

lazy_static! {
    static ref NTCP2_STYLE: I2PString = I2PString::new("NTCP2");
    static ref NTCP2_VERSION: I2PString = I2PString::new("2");
    static ref NTCP2_OPT_V: I2PString = I2PString::new("v");
    static ref NTCP2_OPT_S: I2PString = I2PString::new("s");
    static ref NTCP2_OPT_I: I2PString = I2PString::new("i");
    static ref NTCP2_NOISE_PROTOCOL_NAME: &'static str =
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

#[cfg_attr(tarpaulin, skip)]
impl fmt::Debug for Block {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Block::DateTime(ts) => format!("DateTime ({})", ts).fmt(formatter),
            Block::Options(_) => "Options".fmt(formatter),
            Block::RouterInfo(ref ri, ref flags) => format!(
                "RouterInfo ({}, flood: {})",
                ri.router_id.hash(),
                flags.flood
            )
            .fmt(formatter),
            Block::Message(_) => "I2NP message".fmt(formatter),
            Block::Termination(_, rsn, _) => format!(
                "Termination (reason: {} - {})",
                rsn,
                match rsn {
                    0 => "unspecified",
                    1 => "termination received",
                    2 => "idle timeout",
                    3 => "router shutdown",
                    4 => "data phase AEAD failure",
                    5 => "incompatible options",
                    6 => "incompatible signature type",
                    7 => "clock skew",
                    8 => "padding violation",
                    9 => "AEAD framing error",
                    10 => "payload format error",
                    11 => "message 1 error",
                    12 => "message 2 error",
                    13 => "message 3 error",
                    14 => "intra-frame read timeout",
                    15 => "RI signature verification fail",
                    16 => "s parameter missing, invalid, or mismatched in RouterInfo",
                    17 => "banned",
                    _ => "unknown",
                }
            )
            .fmt(formatter),
            Block::Padding(size) => format!("Padding ({} bytes)", size).fmt(formatter),
            Block::Unknown(blk, ref data) => {
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
        if self.next_len.is_none() {
            if buf.len() < 2 {
                return Ok(None);
            }

            // Update masker state
            let mut masker = self.dec_len_masker;
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
                let msg_len = sz + 16;

                let start = buf.len();
                buf.extend(repeat(0).take(2 + msg_len));

                // Update masker state
                let mut masker = self.enc_len_masker;
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
    outbound: SessionRx<Block>,
    cached_ob_block: Option<Block>,
}

impl<T, C, D> Session<T, C, D>
where
    T: AsyncRead + AsyncWrite,
    C: Decoder<Item = Frame, Error = io::Error>,
    C: Encoder<Item = Frame, Error = io::Error>,
    D: Distributor,
{
    fn new(
        ri: &RouterIdentity,
        upstream: Framed<T, C>,
        session_refs: SessionRefs<Block, D>,
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
            cached_ob_block: None,
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
        // Write cached block, if any
        let mut write_ready = true;
        if let Some(block) = self.cached_ob_block.take() {
            match self.ob.start_send(block)? {
                AsyncSink::Ready => (),
                AsyncSink::NotReady(block) => {
                    self.cached_ob_block = Some(block);
                    write_ready = false;
                }
            }
        }

        // Write blocks
        while write_ready {
            match self.outbound.poll().unwrap() {
                Async::Ready(Some(block)) => match self.ob.start_send(block)? {
                    AsyncSink::Ready => (),
                    AsyncSink::NotReady(block) => {
                        self.cached_ob_block = Some(block);
                        write_ready = false;
                    }
                },
                _ => break,
            }
        }

        // Flush blocks
        self.ob.poll_complete()?;

        // Read blocks
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
    ctx: SessionContext<Block>,
    upstream: SplitStream<Framed<T, C>>,
    cached_msgs: VecDeque<Message>,
}

impl<T, C> InboundSession<T, C>
where
    T: AsyncRead + AsyncWrite,
    C: Decoder<Item = Frame, Error = io::Error>,
    C: Encoder<Item = Frame, Error = io::Error>,
{
    fn new(ctx: SessionContext<Block>, upstream: SplitStream<Framed<T, C>>) -> Self {
        InboundSession {
            ctx,
            upstream,
            cached_msgs: VecDeque::new(),
        }
    }

    /// Handles a block at the session level. Optionally returns a message that
    /// should be distributed.
    fn handle_block(&self, block: Block) -> Option<Message> {
        match block {
            Block::RouterInfo(ri, _flags) => {
                // Validate hash
                if ri.router_id.hash() != self.ctx.hash {
                    warn!("Received invalid RouterInfo block from {}", self.ctx.hash);
                    return None;
                }

                // Treat as a DatabaseStore
                debug!(
                    "Converting RouterInfo block from {} into DatabaseStore message",
                    self.ctx.hash
                );
                // TODO: Fake-store if we are a FF and flood flag is set
                let fake_ds = Message::from_payload(MessagePayload::DatabaseStore(
                    DatabaseStore::from_ri(ri, None),
                ));

                Some(fake_ds)
            }
            Block::Message(msg) => Some(msg),
            Block::Padding(_) => {
                trace!("Dropping padding block from {}: {:?}", self.ctx.hash, block);
                None
            }
            Block::Termination(_, _, _) => {
                info!("Peer {} terminated session: {:?}", self.ctx.hash, block);
                // TODO: Send a Termination in reply, then shut down
                None
            }
            Block::Unknown(_, _) => {
                debug!("Dropping unknown block: {:?}", block);
                None
            }
            block => {
                // TODO: Do something
                debug!(
                    "Dropping unhandled block from {}: {:?}",
                    self.ctx.hash, block
                );
                None
            }
        }
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
            // Return any cached messages
            while let Some(msg) = self.cached_msgs.pop_front() {
                return Ok(Async::Ready(Some((self.ctx.hash.clone(), msg))));
            }

            // Read frames
            match try_ready!(self.upstream.poll()) {
                Some(frame) => {
                    // TODO: Validate block ordering within the frame
                    for block in frame {
                        if let Some(msg) = self.handle_block(block) {
                            self.cached_msgs.push_back(msg);
                        }
                    }
                }
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
    cached_blocks: VecDeque<Block>,
}

impl<T, C> OutboundSession<T, C>
where
    T: AsyncRead + AsyncWrite,
    C: Decoder<Item = Frame, Error = io::Error>,
    C: Encoder<Item = Frame, Error = io::Error>,
{
    fn new(downstream: SplitSink<Framed<T, C>>) -> Self {
        OutboundSession {
            downstream,
            cached_blocks: VecDeque::new(),
        }
    }
}

impl<T, C> Sink for OutboundSession<T, C>
where
    T: AsyncRead + AsyncWrite,
    C: Decoder<Item = Frame, Error = io::Error>,
    C: Encoder<Item = Frame, Error = io::Error>,
{
    type SinkItem = Block;
    type SinkError = io::Error;

    fn start_send(&mut self, block: Block) -> StartSend<Block, io::Error> {
        self.cached_blocks.push_back(block);

        const BLOCKS_PER_FRAME: usize = 10;
        if self.cached_blocks.len() >= BLOCKS_PER_FRAME {
            // Create frame from blocks
            // TODO: Limit frame size instead of blocks per frame
            // TODO: Add padding
            let frame = self.cached_blocks.drain(0..BLOCKS_PER_FRAME).collect();

            match self.downstream.start_send(frame)? {
                AsyncSink::Ready => Ok(AsyncSink::Ready),
                AsyncSink::NotReady(frame) => {
                    for block in frame.into_iter().rev() {
                        self.cached_blocks.push_front(block);
                    }
                    // Guaranteed to return a block
                    let orig_block = self.cached_blocks.pop_back().unwrap();
                    return Ok(AsyncSink::NotReady(orig_block));
                }
            }
        } else {
            Ok(AsyncSink::Ready)
        }
    }

    fn poll_complete(&mut self) -> Poll<(), io::Error> {
        // Package any remaining blocks in a frame
        if !self.cached_blocks.is_empty() {
            // Create frame from blocks
            // TODO: Limit frame size instead of blocks per frame
            // TODO: Add padding
            let frame = self.cached_blocks.drain(..).collect();

            if let AsyncSink::NotReady(frame) = self.downstream.start_send(frame)? {
                self.cached_blocks.extend(frame);
                return Ok(Async::NotReady);
            }
        }

        // Flush frames
        self.downstream.poll_complete()
    }
}

//
// Connection management engine
//

pub struct Manager<D: Distributor> {
    addr: SocketAddr,
    static_private_key: Vec<u8>,
    static_public_key: Vec<u8>,
    aesobfse_iv: [u8; 16],
    session_manager: SessionManager<Block, D>,
    ctx: Option<Arc<Context>>,
}

impl<D: Distributor> Manager<D> {
    pub fn new(addr: SocketAddr, distributor: D) -> Self {
        let builder: Builder<'_> = Builder::new(NTCP2_NOISE_PROTOCOL_NAME.parse().unwrap());
        let dh = builder.generate_keypair().unwrap();

        let mut aesobfse_iv = [0; 16];
        let mut rng = OsRng::new().expect("should be able to construct RNG");
        rng.fill(&mut aesobfse_iv[..]);

        Manager {
            addr,
            static_private_key: dh.private,
            static_public_key: dh.public,
            aesobfse_iv,
            session_manager: session::new_manager(distributor),
            ctx: None,
        }
    }

    pub fn from_file(addr: SocketAddr, path: &str, distributor: D) -> io::Result<Self> {
        let mut keys = File::open(path)?;
        let mut data: Vec<u8> = Vec::new();
        keys.read_to_end(&mut data)?;

        let mut static_private_key = Vec::with_capacity(32);
        let mut static_public_key = Vec::with_capacity(32);
        let mut aesobfse_iv = [0; 16];

        static_private_key.extend_from_slice(&data[..32]);
        static_public_key.extend_from_slice(&data[32..64]);
        aesobfse_iv.copy_from_slice(&data[64..]);

        Ok(Manager {
            addr,
            static_private_key: static_private_key.clone(),
            static_public_key,
            aesobfse_iv,
            session_manager: session::new_manager(distributor),
            ctx: None,
        })
    }

    pub fn to_file(&self, path: &str) -> io::Result<()> {
        let mut data = Vec::with_capacity(96);
        data.write_all(&self.static_private_key)?;
        data.write_all(&self.static_public_key)?;
        data.write_all(&self.aesobfse_iv)?;
        let mut keys = File::create(path)?;
        keys.write(&data).map(|_| ())
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
            static_private_key: self.static_private_key.clone(),
            session_refs: self.session_manager.refs(),
        }
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

    pub fn listen(&self, own_rid: &RouterIdentity) -> impl Future<Item = (), Error = io::Error> {
        info!("Listening on {}", self.addr);

        // Bind to the address
        let listener = TcpListener::bind(&self.addr).unwrap();
        let static_key = self.static_private_key.clone();
        let aesobfse_key = own_rid.hash().0;
        let aesobfse_iv = self.aesobfse_iv;

        // Give each incoming connection the references it needs
        let session_refs = self.session_manager.refs();
        let conns = listener.incoming().zip(session_refs);

        // For each incoming connection:
        conns.for_each(move |(conn, session_refs)| {
            info!("Incoming connection!");
            // Execute the handshake
            let conn = handshake::IBHandshake::new(conn, &static_key, &aesobfse_key, &aesobfse_iv);

            // Once connected:
            let process_conn = conn
                .and_then(|(ri, conn)| {
                    let peer_hash = ri.router_id.hash();
                    let session = Session::new(&ri.router_id, conn, session_refs);

                    // Treat RouterInfo from handshake as a DatabaseStore
                    debug!(
                        "Converting RouterInfo block from {} into DatabaseStore message",
                        peer_hash
                    );
                    // TODO: Fake-store if we are a FF and flood flag is set
                    let fake_ds = Message::from_payload(MessagePayload::DatabaseStore(
                        DatabaseStore::from_ri(ri, None),
                    ));
                    let stored = session.distributor.handle(peer_hash, fake_ds);

                    // Start the session
                    stored
                        .map(|_| session)
                        .map_err(|_| io::Error::new(io::ErrorKind::Other, "A subsystem is down!"))
                })
                .and_then(|session| session);

            spawn(process_conn.map_err(|e| error!("Error while listening: {:?}", e)));
            Ok(())
        })
    }

    pub fn connect(
        &self,
        own_ri: &RouterInfo,
        peer_ri: RouterInfo,
    ) -> io::Result<impl Future<Item = (), Error = io::Error>> {
        connect(
            &self.static_private_key,
            own_ri,
            peer_ri,
            self.session_manager.refs(),
        )
    }
}

fn connect<D: Distributor>(
    static_private_key: &[u8],
    own_ri: &RouterInfo,
    peer_ri: RouterInfo,
    session_refs: SessionRefs<Block, D>,
) -> io::Result<impl Future<Item = (), Error = io::Error>> {
    // Connect to the peer
    let transport = match handshake::OBHandshake::new(
        |sa| Box::new(TcpStream::connect(sa)),
        static_private_key,
        own_ri,
        peer_ri,
    ) {
        Ok(t) => t,
        Err(e) => return io_err!(InvalidData, e),
    };

    // Add a timeout
    let timed = Timeout::new(transport, Duration::new(10, 0))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e));

    // Once connected:
    Ok(timed.and_then(|(ri, conn)| {
        let session = Session::new(&ri, conn, session_refs);
        spawn(session.map_err(|_| ()));
        Ok(())
    }))
}

impl<D: Distributor> Transport for Manager<D> {
    fn is_established(&self, hash: &Hash) -> bool {
        self.session_manager.have_session(hash)
    }

    fn bid(&self, peer: &RouterInfo, msg_size: usize) -> Option<Bid> {
        if msg_size > NTCP2_MTU {
            return None;
        }

        let filter = |ra: &RouterAddress| {
            match ra.option(&NTCP2_OPT_V) {
                Some(v) => {
                    if !v.to_csv().contains(&NTCP2_VERSION) {
                        return false;
                    }
                }
                None => return false,
            };
            ra.option(&NTCP2_OPT_S).is_some() && ra.option(&NTCP2_OPT_I).is_some()
        };

        if peer.address(&NTCP2_STYLE, filter).is_none()
            && peer.address(&NTCP_STYLE, filter).is_none()
        {
            return None;
        }

        Some(Bid {
            bid: if self.is_established(&peer.router_id.hash()) {
                10
            } else {
                40
            },
            sink: Box::new(self.sink()),
        })
    }
}

pub struct OutboundSink<D: Distributor> {
    ctx: Arc<Context>,
    static_private_key: Vec<u8>,
    session_refs: SessionRefs<Block, D>,
}

impl<D: Distributor> Sink for OutboundSink<D> {
    type SinkItem = (RouterInfo, Message);
    type SinkError = io::Error;

    fn start_send(
        &mut self,
        (peer, msg): Self::SinkItem,
    ) -> StartSend<Self::SinkItem, Self::SinkError> {
        let static_private_key = self.static_private_key.clone();
        let session_refs = self.session_refs.clone();

        match self
            .session_refs
            .state
            .send(&peer.router_id.hash(), Block::Message(msg), || {
                // Connect to the peer
                let session_refs = session_refs.clone();
                match connect(
                    &static_private_key,
                    &self.ctx.ri.read().unwrap(),
                    peer.clone(),
                    session_refs,
                ) {
                    Ok(f) => spawn(f.map_err(|e| {
                        error!("Error while connecting: {}", e);
                    })),
                    Err(e) => error!("{}", e),
                }
            }) {
            Ok(AsyncSink::Ready) => Ok(AsyncSink::Ready),
            Ok(AsyncSink::NotReady(Block::Message(msg))) => Ok(AsyncSink::NotReady((peer, msg))),
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
    use std::io::{self, Read, Write};
    use std::iter::repeat;
    use tokio_codec::{Decoder, Encoder};

    use super::{frame, Frame, Manager, Session, NTCP2_MTU};
    use crate::i2np::Message;
    use crate::router::mock::{mock_context, MockDistributor};
    use crate::transport::tests::{AliceNet, BobNet, NetworkCable};

    struct TestCodec;

    impl Decoder for TestCodec {
        type Item = Frame;
        type Error = io::Error;

        fn decode(&mut self, buf: &mut BytesMut) -> io::Result<Option<Frame>> {
            if buf.len() < 3 {
                return Ok(None);
            }
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
            buf.extend(repeat(0).take(NTCP2_MTU));

            match frame::gen_frame((buf, start), &frame).map(|tup| tup.1) {
                Ok(sz) => {
                    buf.truncate(sz);
                    Ok(())
                }
                Err(e) => match e {
                    GenError::BufferTooSmall(sz) => Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("message ({}) larger than MTU ({})", sz - start, NTCP2_MTU),
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

    const DUMMY_MSG_NTCP2_DATA: &[u8] = &[
        0x03, 0x00, 0x17, 0x14, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x90, 0xbe, 0x58, 0x00, 0x00, 0x00,
        0x0a, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
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
            let mut session = Session::new(&rid, alice_framed, manager.session_manager.refs());

            // Pass it through the session, now it's on the wire
            session.poll().unwrap();
            received.clear();
            assert!(bob_net.read_to_end(&mut received).is_err());
            assert_eq!(&received, &DUMMY_MSG_NTCP2_DATA);

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
        let mut session = Session::new(&rid, bob_framed, manager.session_manager.refs());

        // Run on a task context
        lazy(move || {
            let mut alice_net = AliceNet::new(cable);
            assert!(alice_net.write_all(DUMMY_MSG_NTCP2_DATA).is_ok());

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
