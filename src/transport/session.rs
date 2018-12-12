//! Common structures for managing active sessions over individual transports.

use futures::{sync::mpsc, Async, AsyncSink, Poll, Sink, StartSend, Stream};
use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};

use crate::data::Hash;

//
// Session state
//

/// Shorthand for the transmit half of an Engine-bound message channel.
pub(super) type EngineTx<Frame> = mpsc::UnboundedSender<(Hash, Frame)>;

/// Shorthand for the receive half of an Engine-bound message channel.
pub(super) type EngineRx<Frame> = mpsc::UnboundedReceiver<(Hash, Frame)>;

/// Shorthand for the transmit half of a Session-bound message channel.
type SessionTx<Frame> = mpsc::UnboundedSender<Frame>;

/// Shorthand for the receive half of a Session-bound message channel.
pub(super) type SessionRx<Frame> = mpsc::UnboundedReceiver<Frame>;

struct Shared<F> {
    sessions: HashMap<Hash, SessionTx<F>>,
    pending_sessions: HashMap<Hash, Vec<F>>,
}

impl<F> Shared<F> {
    fn new() -> Self {
        Shared {
            sessions: HashMap::new(),
            pending_sessions: HashMap::new(),
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

    pub(super) fn send<P>(
        &self,
        hash: &Hash,
        frame: F,
        connect_to_peer: P,
    ) -> StartSend<F, mpsc::SendError<F>>
    where
        P: FnOnce(),
    {
        let mut s = self.0.lock().unwrap();

        // If we have an established session, use it.
        if let Some(mut session) = s.sessions.get(hash) {
            session.start_send(frame)
        } else {
            // Cache the frame for sending once we have a session.
            s.pending_sessions
                .entry(hash.clone())
                .or_insert_with(|| {
                    // No pending session, let's create one
                    connect_to_peer();
                    vec![]
                })
                .push(frame);
            Ok(AsyncSink::Ready)
        }
    }

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

        {
            let mut s = state.0.lock().unwrap();

            // If there were any pending messages waiting for the session to
            // open, queue them now for sending.
            if let Some(msgs) = s.pending_sessions.remove(&hash) {
                for msg in msgs {
                    tx.unbounded_send(msg).unwrap();
                }
            }

            // Store the session for future messages
            s.sessions.insert(hash.clone(), tx);
        }

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

impl<F> Clone for SessionRefs<F> {
    fn clone(&self) -> Self {
        SessionRefs {
            state: self.state.clone(),
            engine: self.engine.clone(),
        }
    }
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

pub(super) struct SessionManager<F> {
    state: SessionState<F>,
    inbound: EngineTx<F>,
}

pub(super) fn new_manager<F>() -> (SessionManager<F>, EngineRx<F>) {
    let (inbound, inbound_msg) = mpsc::unbounded();
    let state = SessionState::new();
    (
        SessionManager {
            state: state.clone(),
            inbound,
        },
        inbound_msg,
    )
}

impl<F> SessionManager<F> {
    pub(super) fn refs(&self) -> SessionRefs<F> {
        SessionRefs {
            state: self.state.clone(),
            engine: self.inbound.clone(),
        }
    }

    pub fn have_session(&self, hash: &Hash) -> bool {
        self.state.contains(hash)
    }
}
