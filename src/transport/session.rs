//! Common structures for managing active sessions over individual transports.

use futures::{sync::mpsc, Async, Poll, Stream};
use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};

use super::{Handle, MessageRx, TimestampRx};
use data::Hash;
use i2np::Message;

//
// Session state
//

/// Shorthand for the transmit half of an Engine-bound message channel.
pub(super) type EngineTx<Frame> = mpsc::UnboundedSender<(Hash, Frame)>;

/// Shorthand for the receive half of an Engine-bound message channel.
type EngineRx<Frame> = mpsc::UnboundedReceiver<(Hash, Frame)>;

/// Shorthand for the transmit half of a Session-bound message channel.
type SessionTx<Frame> = mpsc::UnboundedSender<Frame>;

/// Shorthand for the receive half of a Session-bound message channel.
pub(super) type SessionRx<Frame> = mpsc::UnboundedReceiver<Frame>;

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

pub(super) struct SessionState<F>(Arc<Mutex<Shared<F>>>);

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

pub(super) struct SessionContext<F> {
    pub hash: Hash,
    state: SessionState<F>,
}

impl<F> SessionContext<F> {
    pub(super) fn new(hash: Hash, state: SessionState<F>, tx: SessionTx<F>) -> Self {
        info!("Session established with {}", hash);
        state.0.lock().unwrap().sessions.insert(hash.clone(), tx);
        SessionContext { hash, state }
    }
}

impl<F> Drop for SessionContext<F> {
    fn drop(&mut self) {
        info!("Session ended with {}", self.hash);
        self.state.0.lock().unwrap().sessions.remove(&self.hash);
    }
}

pub(super) struct SessionRefs<F> {
    pub(super) state: SessionState<F>,
    pub(super) engine: EngineTx<F>,
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

pub(super) struct SessionEngine<F> {
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

    pub(super) fn refs(&self) -> SessionRefs<F> {
        SessionRefs {
            state: self.state.clone(),
            engine: self.inbound.0.clone(),
        }
    }

    pub fn have_session(&self, hash: &Hash) -> bool {
        self.state.contains(hash)
    }

    pub fn poll<P, Q>(
        &mut self,
        frame_message: P,
        frame_timestamp: Q,
    ) -> Poll<Option<(Hash, F)>, ()>
    where
        P: Fn(Message) -> F,
        Q: Fn(u32) -> F,
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

        // Return the next inbound frame
        self.inbound.1.poll()
    }
}
