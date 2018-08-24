use futures::{sync::mpsc, task, Async, Future, Poll, Sink, Stream};
use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};
use tokio_codec::{Decoder, Encoder, Framed};
use tokio_io::{AsyncRead, AsyncWrite};

use data::{Hash, RouterIdentity};

//
// Session state
//

/// Shorthand for the transmit half of an Engine-bound message channel.
pub type EngineTx<Frame> = mpsc::UnboundedSender<(Hash, Frame)>;

/// Shorthand for the receive half of an Engine-bound message channel.
pub type EngineRx<Frame> = mpsc::UnboundedReceiver<(Hash, Frame)>;

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

pub struct SessionState<F>(Arc<Mutex<Shared<F>>>);

impl<F> Clone for SessionState<F> {
    fn clone(&self) -> Self {
        SessionState(self.0.clone())
    }
}

impl<F> SessionState<F> {
    pub fn get<G>(&self, hash: &Hash, func: G)
    where
        G: FnOnce(Option<&SessionTx<F>>),
    {
        func(self.0.lock().unwrap().sessions.get(hash))
    }
}

impl<F> SessionState<F> {
    pub fn new() -> Self {
        SessionState(Arc::new(Mutex::new(Shared::new())))
    }
}

pub struct Session<T, C, F> {
    ri: RouterIdentity,
    upstream: Framed<T, C>,
    state: SessionState<F>,
    engine: EngineTx<F>,
    outbound: SessionRx<F>,
}

impl<T, C, F> Session<T, C, F> {
    pub fn new(
        ri: RouterIdentity,
        upstream: Framed<T, C>,
        state: SessionState<F>,
        engine: EngineTx<F>,
    ) -> Self {
        info!("Session established with {}", ri.hash());
        let (tx, rx) = mpsc::unbounded();
        state.0.lock().unwrap().sessions.insert(ri.hash(), tx);
        Session {
            ri,
            upstream,
            state,
            engine,
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

impl<T, C, F> Drop for Session<T, C, F> {
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

impl<F> SessionRefs<F> {
    pub fn new(state: SessionState<F>, engine: EngineTx<F>) -> Self {
        SessionRefs { state, engine }
    }
}

impl<F> Stream for SessionRefs<F> {
    type Item = (SessionState<F>, EngineTx<F>);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        Ok(Async::Ready(Some((
            self.state.clone(),
            self.engine.clone(),
        ))))
    }
}
