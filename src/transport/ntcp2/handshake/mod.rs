use byteorder::{LittleEndian, ReadBytesExt};
use cookie_factory::GenError;
use futures::{Async, Future, Poll};
use i2p_snow::{Builder, Session};
use nom::Err;
use rand::{rngs::OsRng, Rng};
use siphasher::sip::SipHasher;
use std::io;
use std::net::SocketAddr;
use std::ops::AddAssign;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio_codec::{Decoder, Framed};
use tokio_io::{
    self,
    io::{ReadExact, WriteAll},
    AsyncRead, AsyncWrite, IoFuture,
};

use super::{
    frame, Block, Codec, NTCP2_MTU, NTCP2_NOISE_PROTOCOL_NAME, NTCP2_OPT_I, NTCP2_OPT_S,
    NTCP2_OPT_V, NTCP2_STYLE, NTCP2_VERSION,
};
use constants::I2P_BASE64;
use data::{RouterAddress, RouterIdentity, RouterInfo};
use transport::ntcp::NTCP_STYLE;

const SESSION_REQUEST_PT_LEN: usize = 16;
const SESSION_REQUEST_CT_LEN: usize = 32 + SESSION_REQUEST_PT_LEN + 16;
const SESSION_CREATED_PT_LEN: usize = 16;
const SESSION_CREATED_CT_LEN: usize = 32 + SESSION_CREATED_PT_LEN + 16;

macro_rules! try_poll {
    ($f:expr, $parent:expr, $noise:expr) => {
        match $f.poll()? {
            Async::Ready(t) => t,
            Async::NotReady => {
                $parent.noise = Some($noise);
                return Ok(Async::NotReady);
            }
        }
    };
}

macro_rules! io_err {
    ($err_kind:ident, $err_msg:expr) => {
        Err(io::Error::new(io::ErrorKind::$err_kind, $err_msg))
    };
}

//
// Establishment handshake
//

#[allow(enum_variant_names)]
enum IBHandshakeState<T> {
    SessionRequest(ReadExact<T, Vec<u8>>),
    SessionRequestPadding(ReadExact<T, Vec<u8>>),
    SessionCreated((WriteAll<T, Vec<u8>>, SystemTime)),
    SessionConfirmed((ReadExact<T, Vec<u8>>, SystemTime)),
}

pub struct IBHandshake<T> {
    noise: Option<Session>,
    sclen: usize,
    state: IBHandshakeState<T>,
}

impl<T> IBHandshake<T>
where
    T: AsyncRead + AsyncWrite,
    T: Send + 'static,
{
    pub fn new(conn: T, static_key: &[u8], aesobfse_key: &[u8], aesobfse_iv: &[u8; 16]) -> Self {
        // Initialize our responder NoiseSession using a builder.
        let builder: Builder = Builder::new(NTCP2_NOISE_PROTOCOL_NAME.parse().unwrap());
        let noise = builder
            .local_private_key(&static_key)
            .aesobfse(&aesobfse_key, &aesobfse_iv)
            .enable_ask()
            .build_responder()
            .unwrap();
        let state = IBHandshakeState::SessionRequest(tokio_io::io::read_exact(
            conn,
            vec![0u8; SESSION_REQUEST_CT_LEN],
        ));
        IBHandshake {
            noise: Some(noise),
            sclen: 0,
            state,
        }
    }
}

impl<T> Future for IBHandshake<T>
where
    T: AsyncRead + AsyncWrite,
    T: Send + 'static,
{
    type Item = (RouterInfo, Framed<T, Codec>);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            let mut noise = self.noise.take().unwrap();
            let next_state = match self.state {
                IBHandshakeState::SessionRequest(ref mut f) => {
                    let (conn, msg) = try_poll!(f, self, noise);

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
                    self.sclen = sclen;

                    IBHandshakeState::SessionRequestPadding(tokio_io::io::read_exact(
                        conn,
                        vec![0u8; padlen],
                    ))
                }
                IBHandshakeState::SessionRequestPadding(ref mut f) => {
                    let (conn, padding) = try_poll!(f, self, noise);

                    noise.set_h_data(2, &padding).unwrap();

                    let now = SystemTime::now();
                    let mut ts_b = now.duration_since(UNIX_EPOCH).expect("Time went backwards");
                    ts_b.add_assign(Duration::from_millis(500));
                    let ts_b = ts_b.as_secs() as u32;

                    let mut rng = OsRng::new().expect("should be able to construct RNG");
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

                    IBHandshakeState::SessionCreated((tokio_io::io::write_all(conn, buf), now))
                }
                IBHandshakeState::SessionCreated((ref mut f, rtt_timer)) => {
                    let (conn, _) = try_poll!(f, self, noise);

                    IBHandshakeState::SessionConfirmed((
                        tokio_io::io::read_exact(conn, vec![0u8; self.sclen + 48]),
                        rtt_timer,
                    ))
                }
                IBHandshakeState::SessionConfirmed((ref mut f, rtt_timer)) => {
                    let (conn, msg) = try_poll!(f, self, noise);

                    // <- s, se
                    debug!("S <- s, se");
                    let mut buf = vec![0u8; msg.len()];
                    let len = noise.read_message(&msg, &mut buf).unwrap();

                    // SessionConfirmed
                    let mut frames = match frame::session_confirmed(&buf[..len]) {
                        Err(Err::Incomplete(n)) => {
                            return io_err!(
                                Other,
                                format!("received incomplete SessionConfirmed, needed: {:?}", n)
                            )
                        }
                        Err(Err::Error(e)) | Err(Err::Failure(e)) => {
                            return io_err!(Other, format!("SessionConfirmed parse error: {:?}", e))
                        }
                        Ok((_, frames)) => frames,
                    };

                    if frames.is_empty() {
                        return io_err!(Other, "No frames in SessionConfirmed");
                    }

                    let ri_a = match frames.remove(0) {
                        Block::RouterInfo(ri, _) => ri,
                        _ => {
                            // TODO: Finish handshake and then return error in Termination block
                            return io_err!(
                                Other,
                                "First frame in SessionConfirmed is not RouterInfo"
                            );
                        }
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

                    return Ok(Async::Ready((ri_a, codec.framed(conn))));
                }
            };
            self.noise = Some(noise);
            self.state = next_state;
        }
    }
}

enum OBHandshakeState<T> {
    Connecting(IoFuture<T>),
    SessionRequest((WriteAll<T, Vec<u8>>, SystemTime)),
    SessionCreated((ReadExact<T, Vec<u8>>, SystemTime)),
    SessionCreatedPadding(ReadExact<T, Vec<u8>>),
    SessionConfirmed(WriteAll<T, Vec<u8>>),
}

pub struct OBHandshake<T> {
    noise: Option<Session>,
    sc_buf: Vec<u8>,
    sc_len: usize,
    peer_ri: RouterInfo,
    state: OBHandshakeState<T>,
}

impl<T> OBHandshake<T>
where
    T: AsyncRead + AsyncWrite,
    T: Send + 'static,
{
    pub fn new<F>(
        conn: F,
        static_key: &[u8],
        own_ri: &RouterInfo,
        peer_ri: RouterInfo,
    ) -> Result<OBHandshake<T>, String>
    where
        F: FnOnce(&SocketAddr) -> IoFuture<T>,
    {
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

        let ra = match peer_ri.address(&NTCP2_STYLE, filter) {
            Some(ra) => ra,
            None => match peer_ri.address(&NTCP_STYLE, filter) {
                Some(ra) => ra,
                None => return Err("No valid NTCP2 addresses".to_string()),
            },
        };

        let addr = ra.addr().unwrap();
        let remote_key = match ra.option(&NTCP2_OPT_S) {
            Some(val) => match I2P_BASE64.decode(val.0.as_bytes()) {
                Ok(key) => key,
                Err(e) => return Err(format!("Invalid static key in address: {}", e)),
            },
            None => return Err("No static key in address".to_string()),
        };

        let aesobfse_key = peer_ri.router_id.hash().0;
        let mut aesobfse_iv = [0; 16];
        match ra.option(&NTCP2_OPT_I) {
            Some(val) => match I2P_BASE64.decode(val.0.as_bytes()) {
                Ok(iv) => aesobfse_iv.copy_from_slice(&iv),
                Err(e) => return Err(format!("Invalid IV in address: {}", e)),
            },
            None => return Err("No IV in address".to_string()),
        }

        let sc_padlen = {
            let mut rng = OsRng::new().expect("should be able to construct RNG");
            // TODO: Sample padding sizes from an appropriate distribution
            rng.gen_range(0, 16)
        };

        let mut sc_buf = vec![0u8; NTCP2_MTU - 16];
        let sc_len = match frame::gen_session_confirmed((&mut sc_buf, 0), own_ri, sc_padlen)
            .map(|tup| tup.1)
        {
            Ok(sz) => sz,
            Err(e) => match e {
                GenError::BufferTooSmall(sz) => {
                    return Err(format!(
                        "SessionConfirmed message ({}) larger than MTU ({})",
                        sz,
                        NTCP2_MTU - 16
                    ))
                }
                GenError::InvalidOffset
                | GenError::CustomError(_)
                | GenError::NotYetImplemented => return Err("could not generate".to_string()),
            },
        };
        sc_buf.truncate(sc_len);
        let sc_len = sc_len + 16;

        // Initialize our initiator NoiseSession using a builder.
        let builder: Builder = Builder::new(NTCP2_NOISE_PROTOCOL_NAME.parse().unwrap());
        let noise = builder
            .local_private_key(&static_key)
            .remote_public_key(&remote_key)
            .aesobfse(&aesobfse_key, &aesobfse_iv)
            .enable_ask()
            .build_initiator()
            .unwrap();

        let state = OBHandshakeState::Connecting(conn(&addr));
        Ok(OBHandshake {
            noise: Some(noise),
            sc_buf,
            sc_len,
            peer_ri,
            state,
        })
    }
}

impl<T> Future for OBHandshake<T>
where
    T: AsyncRead + AsyncWrite,
    T: Send + 'static,
{
    type Item = (RouterIdentity, Framed<T, Codec>);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            let mut noise = self.noise.take().unwrap();
            let next_state = match self.state {
                OBHandshakeState::Connecting(ref mut f) => {
                    let conn = try_poll!(f, self, noise);

                    let now = SystemTime::now();
                    let mut ts_a = now.duration_since(UNIX_EPOCH).expect("Time went backwards");
                    ts_a.add_assign(Duration::from_millis(500));
                    let ts_a = ts_a.as_secs() as u32;

                    let mut rng = OsRng::new().expect("should be able to construct RNG");
                    // TODO: Sample padding sizes from an appropriate distribution
                    let padlen = rng.gen_range(0, 16);

                    // SessionRequest
                    let mut sr_buf = [0u8; SESSION_REQUEST_PT_LEN];
                    match frame::gen_session_request(
                        (&mut sr_buf, 0),
                        2,
                        padlen,
                        self.sc_len as u16,
                        ts_a,
                    )
                    .map(|tup| tup.1)
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

                    OBHandshakeState::SessionRequest((tokio_io::io::write_all(conn, buf), now))
                }

                OBHandshakeState::SessionRequest((ref mut f, rtt_timer)) => {
                    let (conn, _) = try_poll!(f, self, noise);

                    OBHandshakeState::SessionCreated((
                        tokio_io::io::read_exact(conn, vec![0u8; SESSION_CREATED_CT_LEN]),
                        rtt_timer,
                    ))
                }
                OBHandshakeState::SessionCreated((ref mut f, rtt_timer)) => {
                    let (conn, msg) = try_poll!(f, self, noise);

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

                    OBHandshakeState::SessionCreatedPadding(tokio_io::io::read_exact(
                        conn,
                        vec![0u8; padlen],
                    ))
                }
                OBHandshakeState::SessionCreatedPadding(ref mut f) => {
                    let (conn, padding) = try_poll!(f, self, noise);

                    noise.set_h_data(3, &padding).unwrap();

                    // SessionConfirmed

                    // -> s, se
                    debug!("C -> s, se");
                    let mut buf = vec![0u8; NTCP2_MTU];
                    let len = noise.write_message(&self.sc_buf, &mut buf).unwrap();
                    buf.truncate(len);

                    OBHandshakeState::SessionConfirmed(tokio_io::io::write_all(conn, buf))
                }
                OBHandshakeState::SessionConfirmed(ref mut f) => {
                    let (conn, _) = try_poll!(f, self, noise);

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

                    return Ok(Async::Ready((
                        self.peer_ri.router_id.clone(),
                        codec.framed(conn),
                    )));
                }
            };
            self.noise = Some(noise);
            self.state = next_state;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{IBHandshake, IBHandshakeState, OBHandshake, OBHandshakeState};
    use transport::{
        ntcp2::Manager,
        tests::{AliceNet, BobNet, NetworkCable},
    };

    use futures::{done, Async, Future};

    use data::{RouterInfo, RouterSecretKeys};

    macro_rules! test_poll {
        ($node:expr) => {
            match $node.poll() {
                Ok(Async::NotReady) => (),
                Ok(Async::Ready(_)) => panic!("Unexpectedly ready early!"),
                Err(e) => panic!("Unexpected error: {}", e),
            }
        };
    }

    macro_rules! test_state {
        ($alice:expr, $alice_state:ident, $bob:expr, $bob_state:ident) => {
            match (&$alice.state, &$bob.state) {
                (OBHandshakeState::$alice_state(_), IBHandshakeState::$bob_state(_)) => (),
                _ => panic!(),
            }
        };
    }

    #[test]
    fn ntcp2_handshake() {
        // Generate key material
        let alice_ri = {
            let sk = RouterSecretKeys::new();
            let mut ri = RouterInfo::new(sk.rid.clone());
            ri.sign(&sk.signing_private_key);
            ri
        };
        let (
            bob_ri,
            bob_static_public_key,
            bob_static_private_key,
            bob_aesobfse_key,
            bob_aesobfse_iv,
        ) = {
            let sk = RouterSecretKeys::new();
            let (manager, _) = Manager::new("127.0.0.1:0".parse().unwrap());
            let mut ri = RouterInfo::new(sk.rid.clone());
            ri.set_addresses(vec![manager.address()]);
            ri.sign(&sk.signing_private_key);
            (
                ri,
                manager.static_public_key,
                manager.static_private_key,
                sk.rid.hash().0,
                manager.aesobfse_iv,
            )
        };

        // Set up the network
        let cable = NetworkCable::new();
        let alice_net = AliceNet::new(cable.clone());
        let bob_net = BobNet::new(cable);

        // Set up the handshake
        let mut alice = OBHandshake::new(
            |_| Box::new(done(Ok(alice_net))),
            &bob_static_public_key,
            &alice_ri,
            bob_ri,
        )
        .unwrap();
        let mut bob = IBHandshake::new(
            bob_net,
            &bob_static_private_key,
            &bob_aesobfse_key,
            &bob_aesobfse_iv,
        );
        test_state!(alice, Connecting, bob, SessionRequest);

        // Connect Alice to Bob
        // Alice -> SessionRequest
        test_poll!(alice);
        test_state!(alice, SessionCreated, bob, SessionRequest);

        // Bob <- SessionRequest
        // Bob -> SessionCreated
        test_poll!(bob);
        test_state!(alice, SessionCreated, bob, SessionConfirmed);

        // Alice <- SessionCreated
        // Alice -> SessionConfirmed
        let alice_conn = alice.poll();

        // Bob <- SessionConfirmed
        let bob_conn = bob.poll();

        // Both halves should now be ready
        match (alice_conn, bob_conn) {
            (Ok(Async::Ready(_)), Ok(Async::Ready(_))) => (),
            _ => panic!(),
        }
    }

    #[cfg(all(test, feature = "nightly"))]
    mod transfer {
        use futures::*;
        use std::cmp;
        use std::io;
        use std::time::Duration;
        use test::Bencher;
        use tokio_codec::Framed;
        use tokio_tcp::{TcpListener, TcpStream};

        use data::{RouterInfo, RouterSecretKeys};
        use i2np::{Message, MessagePayload};
        use transport::ntcp2::{
            handshake::{IBHandshake, OBHandshake},
            Block, Codec, Manager,
        };

        const MB: usize = 3 * 1024 * 1024;

        struct Drain {
            sock: Framed<TcpStream, Codec>,
        }

        impl Future for Drain {
            type Item = ();
            type Error = io::Error;

            fn poll(&mut self) -> Poll<(), io::Error> {
                loop {
                    match self.sock.poll()? {
                        Async::Ready(None) => return Ok(Async::Ready(())),
                        _ => {}
                    }
                }
            }
        }

        struct Transfer {
            sock: Framed<TcpStream, Codec>,
            rem: usize,
            chunk: usize,
            frame_size: usize,
        }

        impl Future for Transfer {
            type Item = ();
            type Error = io::Error;

            fn poll(&mut self) -> Poll<(), io::Error> {
                while self.rem > 0 {
                    let mut frame = Vec::with_capacity(self.frame_size);
                    for _ in 0..self.frame_size {
                        let len = cmp::min(self.rem, self.chunk);
                        let buf = DATA[..len].to_vec();

                        frame.push(Block::Message(Message::from_payload(MessagePayload::Data(
                            buf,
                        ))));
                        self.rem -= len;
                        if self.rem == 0 {
                            break;
                        }
                    }
                    self.sock.start_send(frame)?;
                }

                self.sock.poll_complete()?;

                Ok(Async::Ready(()))
            }
        }

        static DATA: [u8; 1024] = [0; 1024];

        fn one_thread(b: &mut Bencher, write_size: usize, frame_size: usize) {
            let addr = "127.0.0.1:0".parse().unwrap();

            // Generate key material
            let alice_ri = {
                let sk = RouterSecretKeys::new();
                let mut ri = RouterInfo::new(sk.rid.clone());
                ri.sign(&sk.signing_private_key);
                ri
            };
            let (
                bob_ri,
                bob_static_public_key,
                bob_static_private_key,
                bob_aesobfse_key,
                bob_aesobfse_iv,
            ) = {
                let sk = RouterSecretKeys::new();
                let (mgr, engine) = Manager::new("127.0.0.1:0".parse().unwrap());
                let mut ri = RouterInfo::new(sk.rid.clone());
                ri.set_addresses(vec![mgr.address()]);
                ri.sign(&sk.signing_private_key);
                (
                    ri,
                    mgr.static_public_key,
                    mgr.static_private_key,
                    sk.rid.hash().0,
                    mgr.aesobfse_iv,
                )
            };

            b.iter(move || {
                let listener = TcpListener::bind(&addr).unwrap();
                let addr = listener.local_addr().unwrap();

                // Spawn a single future that accepts 1 connection, Drain it and drops
                let server = listener
                    .incoming()
                    .into_future()
                    .map_err(|(e, _other_incomings)| e)
                    .map(|(connection, _other_incomings)| connection.unwrap())
                    .and_then(|sock| {
                        sock.set_linger(Some(Duration::from_secs(0))).unwrap();
                        IBHandshake::new(
                            sock,
                            &bob_static_private_key,
                            &bob_aesobfse_key,
                            &bob_aesobfse_iv,
                        )
                    })
                    .and_then(|(ri, conn)| {
                        let drain = Drain { sock: conn };
                        drain
                            .map(|_| ())
                            .map_err(|e| panic!("server error: {:?}", e))
                    });

                let client = OBHandshake::new(
                    |sa| Box::new(TcpStream::connect(&addr)),
                    &bob_static_public_key,
                    &alice_ri,
                    bob_ri.clone(),
                )
                .unwrap()
                .and_then(move |(ri, conn)| Transfer {
                    sock: conn,
                    rem: MB,
                    chunk: write_size,
                    frame_size,
                })
                .map_err(|e| panic!("client err: {:?}", e));

                server.join(client).wait().unwrap();
            });
        }

        mod small_chunks {
            use test::Bencher;

            #[bench]
            fn packed_frames(b: &mut Bencher) {
                super::one_thread(b, 32, 800);
            }

            #[bench]
            fn separate_frames(b: &mut Bencher) {
                super::one_thread(b, 32, 1);
            }
        }

        mod big_chunks {
            use test::Bencher;

            #[bench]
            fn packed_frames(b: &mut Bencher) {
                super::one_thread(b, 1_024, 50);
            }

            #[bench]
            fn separate_frames(b: &mut Bencher) {
                super::one_thread(b, 1_024, 1);
            }
        }
    }
}
