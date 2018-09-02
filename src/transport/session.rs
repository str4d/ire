//! Common structures for managing active sessions over individual transports.

use futures::{sync::mpsc, task, Async, Future, Poll, Sink, Stream};
use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};
use tokio_codec::{Decoder, Encoder, Framed};
use tokio_io::{AsyncRead, AsyncWrite};

use super::{Handle, MessageRx, TimestampRx};
use data::{Hash, RouterIdentity};
use i2np::Message;

//
// Session state
//

/// Shorthand for the transmit half of an Engine-bound message channel.
type EngineTx<Frame> = mpsc::UnboundedSender<(Hash, Frame)>;

/// Shorthand for the receive half of an Engine-bound message channel.
type EngineRx<Frame> = mpsc::UnboundedReceiver<(Hash, Frame)>;

/// Shorthand for the transmit half of a Session-bound message channel.
type SessionTx<Frame> = mpsc::UnboundedSender<Frame>;

/// Shorthand for the receive half of a Session-bound message channel.
type SessionRx<Frame> = mpsc::UnboundedReceiver<Frame>;

struct Shared<F> {
    sessions: HashMap<Hash, SessionTx<F>>,
}

impl<F> Shared<F> {
    fn new() -> Self {
        Shared {
            sessions: HashMap::new(),
        }
    }
}

struct SessionState<F>(Arc<Mutex<Shared<F>>>);

impl<F> Clone for SessionState<F> {
    fn clone(&self) -> Self {
        SessionState(self.0.clone())
    }
}

impl<F> SessionState<F> {
    fn contains(&self, hash: &Hash) -> bool {
        self.0.lock().unwrap().sessions.contains_key(hash)
    }

    fn get<G>(&self, hash: &Hash, func: G)
    where
        G: FnOnce(Option<&SessionTx<F>>),
    {
        func(self.0.lock().unwrap().sessions.get(hash))
    }
}

impl<F> SessionState<F> {
    fn new() -> Self {
        SessionState(Arc::new(Mutex::new(Shared::new())))
    }
}

pub struct Session<T, C, F>
where
    T: AsyncRead + AsyncWrite,
    C: Decoder<Item = F, Error = io::Error>,
    C: Encoder<Item = F, Error = io::Error>,
{
    ri: RouterIdentity,
    upstream: Framed<T, C>,
    state: SessionState<F>,
    engine: EngineTx<F>,
    outbound: SessionRx<F>,
}

impl<T, C, F> Session<T, C, F>
where
    T: AsyncRead + AsyncWrite,
    C: Decoder<Item = F, Error = io::Error>,
    C: Encoder<Item = F, Error = io::Error>,
{
    pub fn new(ri: RouterIdentity, upstream: Framed<T, C>, session_refs: SessionRefs<F>) -> Self {
        info!("Session established with {}", ri.hash());
        let (tx, rx) = mpsc::unbounded();
        session_refs
            .state
            .0
            .lock()
            .unwrap()
            .sessions
            .insert(ri.hash(), tx);
        Session {
            ri,
            upstream,
            state: session_refs.state,
            engine: session_refs.engine,
            outbound: rx,
        }
    }
}

impl<T, C, F> Future for Session<T, C, F>
where
    T: AsyncRead + AsyncWrite,
    C: Decoder<Item = F, Error = io::Error>,
    C: Encoder<Item = F, Error = io::Error>,
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

impl<T, C, F> Drop for Session<T, C, F>
where
    T: AsyncRead + AsyncWrite,
    C: Decoder<Item = F, Error = io::Error>,
    C: Encoder<Item = F, Error = io::Error>,
{
    fn drop(&mut self) {
        info!("Session ended with {}", self.ri.hash());
        self.state
            .0
            .lock()
            .unwrap()
            .sessions
            .remove(&self.ri.hash());
    }
}

pub struct SessionRefs<F> {
    state: SessionState<F>,
    engine: EngineTx<F>,
}

impl<F> Stream for SessionRefs<F> {
    type Item = (SessionRefs<F>);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        Ok(Async::Ready(Some(SessionRefs {
            state: self.state.clone(),
            engine: self.engine.clone(),
        })))
    }
}

//
// Connection management engine
//

pub struct SessionEngine<F> {
    state: SessionState<F>,
    handle: Handle,
    inbound: (EngineTx<F>, EngineRx<F>),
    outbound_msg: MessageRx,
    outbound_ts: TimestampRx,
}

impl<F> SessionEngine<F> {
    pub fn new() -> Self {
        let (message, outbound_msg) = mpsc::unbounded();
        let (timestamp, outbound_ts) = mpsc::unbounded();
        SessionEngine {
            state: SessionState::new(),
            inbound: mpsc::unbounded(),
            handle: Handle { message, timestamp },
            outbound_msg,
            outbound_ts,
        }
    }

    pub fn handle(&self) -> Handle {
        self.handle.clone()
    }

    pub fn refs(&self) -> SessionRefs<F> {
        SessionRefs {
            state: self.state.clone(),
            engine: self.inbound.0.clone(),
        }
    }

    pub fn have_session(&self, hash: &Hash) -> bool {
        self.state.contains(hash)
    }

    pub fn poll<P, Q, R>(
        &mut self,
        frame_message: P,
        frame_timestamp: Q,
        on_receive: R,
    ) -> Poll<(), ()>
    where
        P: Fn(Message) -> F,
        Q: Fn(u32) -> F,
        R: Fn(Hash, F),
    {
        // Write timestamps first
        while let Async::Ready(f) = self.outbound_ts.poll().unwrap() {
            if let Some((hash, ts)) = f {
                self.state.get(&hash, |s| match s {
                    Some(session) => {
                        session.unbounded_send(frame_timestamp(ts)).unwrap();
                    }
                    None => error!("No open session for {}", hash), // TODO: Open session instead of dropping
                });
            }
        }

        // Write messages
        while let Async::Ready(f) = self.outbound_msg.poll().unwrap() {
            if let Some((hash, msg)) = f {
                self.state.get(&hash, |s| match s {
                    Some(session) => {
                        session.unbounded_send(frame_message(msg)).unwrap();
                    }
                    None => error!("No open session for {}", hash), // TODO: Open session instead of dropping
                });
            }
        }

        // Read frames
        while let Async::Ready(f) = self.inbound.1.poll()? {
            if let Some((hash, frame)) = f {
                on_receive(hash, frame);
            } else {
                // EOF was reached. The remote peer has disconnected.
                return Ok(Async::Ready(()));
            }
        }

        // We know we got a `NotReady` from both `self.outbound.1` and `self.inbound.1`,
        // so the contract is respected.
        Ok(Async::NotReady)
    }
}

#[cfg(test)]
mod tests {
    use futures::{lazy, Future};
    use std::io::{Read, Write};
    use std::str::FromStr;
    use tokio_codec::{Decoder, LinesCodec};

    use super::{Session, SessionEngine};
    use data::RouterSecretKeys;
    use i2np::Message;
    use transport::tests::{AliceNet, BobNet, NetworkCable};

    #[test]
    fn session_send() {
        let rid = RouterSecretKeys::new().rid;
        let hash = rid.hash();

        let cable = NetworkCable::new();
        let alice_net = AliceNet::new(cable.clone());
        let alice_framed = LinesCodec::new().framed(alice_net);

        let mut engine = SessionEngine::new();
        let mut session = Session::new(rid, alice_framed, engine.refs());

        // Run on a task context
        lazy(move || {
            let handle = engine.handle();
            handle.send(hash.clone(), Message::dummy_data()).unwrap();

            // Check it has not yet been received
            let mut bob_net = BobNet::new(cable);
            let mut received = String::new();
            assert!(bob_net.read_to_string(&mut received).is_err());
            assert!(received.is_empty());

            // Pass it through the engine, still not received
            engine
                .poll(
                    |m| String::from_str("foo bar baz").unwrap(),
                    |_| panic!(),
                    |h, f| (),
                )
                .unwrap();
            received.clear();
            assert!(bob_net.read_to_string(&mut received).is_err());
            assert!(received.is_empty());

            // Pass it through the session, now it's on the wire
            session.poll().unwrap();
            received.clear();
            assert!(bob_net.read_to_string(&mut received).is_err());
            assert_eq!(received, String::from_str("foo bar baz\n").unwrap());

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
        let bob_framed = LinesCodec::new().framed(bob_net);

        let mut engine = SessionEngine::new();
        let mut session = Session::new(rid, bob_framed, engine.refs());

        // Run on a task context
        lazy(move || {
            let mut alice_net = AliceNet::new(cable);
            assert!(alice_net.write_all(b"foo bar baz\n").is_ok());

            // Check it has not yet been received
            engine
                .poll(|_| panic!(), |_| panic!(), |_, _| panic!())
                .unwrap();

            // Pass it through the session
            session.poll().unwrap();

            // The engine should receive it now
            engine
                .poll(
                    |_| panic!(),
                    |_| panic!(),
                    |h, received| {
                        assert_eq!(h, hash);
                        assert_eq!(received, String::from_str("foo bar baz").unwrap());
                    },
                )
                .unwrap();

            Ok::<(), ()>(())
        }).wait()
            .unwrap();
    }
}
