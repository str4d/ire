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
use futures::{sync::mpsc, task, Async, Future, Poll, Sink, Stream};
use i2p_snow::{self, Builder};
use nom::Err;
use rand::{OsRng, Rng};
use siphasher::sip::SipHasher;
use std::fmt;
use std::fs::File;
use std::hash::Hasher;
use std::io::{self, Read, Write};
use std::iter::repeat;
use std::net::SocketAddr;
use std::time::Duration;
use tokio_codec::{Decoder, Encoder, Framed};
use tokio_executor::spawn;
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_tcp::{TcpListener, TcpStream};
use tokio_timer::Timeout;

use super::{
    session::{
        self, EngineTx, SessionContext, SessionEngine, SessionManager, SessionRefs, SessionRx,
    },
    Bid, Handle, Transport,
};
use constants::I2P_BASE64;
use data::{Hash, I2PString, RouterAddress, RouterIdentity, RouterInfo};
use i2np::{DatabaseStore, Message, MessagePayload};

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

impl fmt::Debug for Block {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Block::DateTime(ts) => format!("DateTime ({})", ts).fmt(formatter),
            Block::Options(_) => "Options".fmt(formatter),
            Block::RouterInfo(ref ri, ref flags) => format!(
                "RouterInfo ({}, flood: {})",
                ri.router_id.hash(),
                flags.flood
            ).fmt(formatter),
            Block::Message(_) => "I2NP message".fmt(formatter),
            Block::Termination(_, rsn, _) => {
                format!("Termination (reason: {})", rsn).fmt(formatter)
            }
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
        if let None = self.next_len {
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
                let mut msg_len = sz + 16;

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

struct Session<T, C>
where
    T: AsyncRead + AsyncWrite,
    C: Decoder<Item = Frame, Error = io::Error>,
    C: Encoder<Item = Frame, Error = io::Error>,
{
    ctx: SessionContext<Block>,
    upstream: Framed<T, C>,
    engine: EngineTx<Block>,
    outbound: SessionRx<Block>,
}

impl<T, C> Session<T, C>
where
    T: AsyncRead + AsyncWrite,
    C: Decoder<Item = Frame, Error = io::Error>,
    C: Encoder<Item = Frame, Error = io::Error>,
{
    fn new(ri: &RouterIdentity, upstream: Framed<T, C>, session_refs: SessionRefs<Block>) -> Self {
        let (tx, rx) = mpsc::unbounded();
        Session {
            ctx: SessionContext::new(ri.hash(), session_refs.state, tx),
            upstream,
            engine: session_refs.engine,
            outbound: rx,
        }
    }

    /// Handles a block at the session level. Optionally returns a block that
    /// should be sent onwards to the transport engine.
    fn handle_block(&self, block: Block) -> Option<Block> {
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

                Some(Block::Message(fake_ds))
            }
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
            block => Some(block),
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
            let mut done = false;

            // Create frame from blocks
            const BLOCKS_PER_FRAME: usize = 10;
            let mut frame = Vec::with_capacity(BLOCKS_PER_FRAME);
            // TODO: Limit frame size instead of blocks per frame
            for _ in 0..BLOCKS_PER_FRAME {
                match self.outbound.poll().unwrap() {
                    Async::Ready(Some(block)) => {
                        frame.push(block);
                    }
                    _ => {
                        done = true;
                        break;
                    }
                }
            }

            if !frame.is_empty() {
                // TODO: Add padding
                self.upstream.start_send(frame)?;
            }

            // If this is the last iteration, the loop will break even
            // though there could still be frames to read. Because we did
            // not reach `Async::NotReady`, we have to notify ourselves
            // in order to tell the executor to schedule the task again.
            if i + 1 == FRAMES_PER_TICK && !done {
                task::current().notify();
            }
        }

        // Flush frames
        self.upstream.poll_complete()?;

        // Read frames
        while let Async::Ready(f) = self.upstream.poll()? {
            if let Some(frame) = f {
                // TODO: Validate block ordering within the frame
                for block in frame {
                    if let Some(block) = self.handle_block(block) {
                        self.engine
                            .unbounded_send((self.ctx.hash.clone(), block))
                            .unwrap()
                    }
                }
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

pub struct Manager {
    addr: SocketAddr,
    static_private_key: Vec<u8>,
    static_public_key: Vec<u8>,
    aesobfse_iv: [u8; 16],
    session_manager: SessionManager<Block>,
}

pub struct Engine {
    session_engine: SessionEngine<Block>,
}

impl Manager {
    pub fn new(addr: SocketAddr) -> (Self, Engine) {
        let builder: Builder = Builder::new(NTCP2_NOISE_PROTOCOL_NAME.parse().unwrap());
        let dh = builder.generate_keypair().unwrap();

        let mut aesobfse_iv = [0; 16];
        let mut rng = OsRng::new().expect("should be able to construct RNG");
        rng.fill(&mut aesobfse_iv[..]);

        let (session_manager, session_engine) = session::new_manager();

        (
            Manager {
                addr,
                static_private_key: dh.private,
                static_public_key: dh.public,
                aesobfse_iv,
                session_manager,
            },
            Engine { session_engine },
        )
    }

    pub fn from_file(addr: SocketAddr, path: &str) -> io::Result<(Self, Engine)> {
        let mut keys = File::open(path)?;
        let mut data: Vec<u8> = Vec::new();
        keys.read_to_end(&mut data)?;

        let mut static_private_key = Vec::with_capacity(32);
        let mut static_public_key = Vec::with_capacity(32);
        let mut aesobfse_iv = [0; 16];

        static_private_key.extend_from_slice(&data[..32]);
        static_public_key.extend_from_slice(&data[32..64]);
        aesobfse_iv.copy_from_slice(&data[64..]);

        let (session_manager, session_engine) = session::new_manager();

        Ok((
            Manager {
                addr,
                static_private_key,
                static_public_key,
                aesobfse_iv,
                session_manager,
            },
            Engine { session_engine },
        ))
    }

    pub fn to_file(&self, path: &str) -> io::Result<()> {
        let mut data = Vec::with_capacity(96);
        data.write_all(&self.static_private_key)?;
        data.write_all(&self.static_public_key)?;
        data.write_all(&self.aesobfse_iv)?;
        let mut keys = File::create(path)?;
        keys.write(&data).map(|_| ())
    }

    pub fn handle(&self) -> Handle {
        self.session_manager.handle()
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
            let process_conn = conn.and_then(|(ri, conn)| Session::new(&ri, conn, session_refs));

            spawn(process_conn.map_err(|e| error!("Error while listening: {:?}", e)));
            Ok(())
        })
    }

    pub fn connect(
        &self,
        own_ri: &RouterInfo,
        peer_ri: RouterInfo,
    ) -> io::Result<impl Future<Item = (), Error = io::Error>> {
        // Connect to the peer
        let transport = match handshake::OBHandshake::new(
            |sa| Box::new(TcpStream::connect(sa)),
            &self.static_private_key,
            &own_ri,
            peer_ri,
        ) {
            Ok(t) => t,
            Err(e) => return io_err!(InvalidData, e),
        };

        // Add a timeout
        let timed = Timeout::new(transport, Duration::new(10, 0))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e));

        // Once connected:
        let session_refs = self.session_manager.refs();
        Ok(timed.and_then(|(ri, conn)| {
            let session = Session::new(&ri, conn, session_refs);
            spawn(session.map_err(|_| ()));
            Ok(())
        }))
    }
}

impl Transport for Manager {
    fn bid(&self, hash: &Hash, msg_size: usize) -> Option<Bid> {
        if msg_size > NTCP2_MTU {
            return None;
        }

        Some(Bid {
            bid: if self.session_manager.have_session(hash) {
                10
            } else {
                40
            },
            handle: self.session_manager.handle(),
        })
    }
}

impl Stream for Engine {
    type Item = (Hash, Message);
    type Error = ();

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        while let Async::Ready(f) = self.session_engine.poll(Block::Message, Block::DateTime)? {
            match f {
                Some((from, Block::Message(msg))) => return Ok(Some((from, msg)).into()),
                Some((from, block)) => {
                    // TODO: Do something
                    debug!("Received block from {}: {:?}", from, block);
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

    use super::{frame, session, Block, Frame, Session, NTCP2_MTU};
    use data::RouterSecretKeys;
    use i2np::Message;
    use transport::tests::{AliceNet, BobNet, NetworkCable};

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

    const DUMMY_MSG_NTCP2_DATA: &'static [u8] = &[
        0x03, 0x00, 0x17, 0x14, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x90, 0xbe, 0x58, 0x00, 0x00, 0x00,
        0x0a, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    ];

    #[test]
    fn session_send() {
        let rid = RouterSecretKeys::new().rid;
        let hash = rid.hash();

        let cable = NetworkCable::new();
        let alice_net = AliceNet::new(cable.clone());
        let alice_framed = TestCodec {}.framed(alice_net);

        let (manager, mut engine) = session::new_manager();
        let mut session = Session::new(&rid, alice_framed, manager.refs());

        // Run on a task context
        lazy(move || {
            let handle = manager.handle();
            handle.send(hash.clone(), Message::dummy_data()).unwrap();

            // Check it has not yet been received
            let mut bob_net = BobNet::new(cable);
            let mut received = Vec::new();
            assert!(bob_net.read_to_end(&mut received).is_err());
            assert!(received.is_empty());

            // Pass it through the engine, still not received
            engine.poll(Block::Message, |_| panic!()).unwrap();
            received.clear();
            assert!(bob_net.read_to_end(&mut received).is_err());
            assert!(received.is_empty());

            // Pass it through the session, now it's on the wire
            session.poll().unwrap();
            received.clear();
            assert!(bob_net.read_to_end(&mut received).is_err());
            assert_eq!(&received, &DUMMY_MSG_NTCP2_DATA);

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

        let (manager, mut engine) = session::new_manager();
        let mut session = Session::new(&rid, bob_framed, manager.refs());

        // Run on a task context
        lazy(move || {
            let mut alice_net = AliceNet::new(cable);
            assert!(alice_net.write_all(DUMMY_MSG_NTCP2_DATA).is_ok());

            // Check it has not yet been received
            engine.poll(|_| panic!(), |_| panic!()).unwrap();

            // Pass it through the session
            session.poll().unwrap();

            // The engine should receive it now
            match engine.poll(|_| panic!(), |_| panic!()).unwrap() {
                Async::Ready(Some((h, block))) => {
                    assert_eq!(h, hash);
                    match block {
                        Block::Message(msg) => {
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
