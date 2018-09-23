use futures::Future;
use std::io;
use std::sync::{Arc, Mutex, Weak};

use data::{Hash, RouterSecretKeys};
use i2np::Message;

mod builder;
mod config;
mod mock;
pub mod types;

pub use self::builder::Builder;
pub use self::config::Config;

enum RouterState {
    Stopped,
    Starting,
    Running,
    Stopping,
}

/// An I2P router.
pub struct Router {
    inner: Arc<Mutex<Inner>>,
}

/// A reference to a router.
#[derive(Clone)]
pub struct Handle {
    inner: Weak<Inner>,
}

struct Inner {
    state: RouterState,
    keys: RouterSecretKeys,
    comms: Box<types::CommSystem>,
    peers: Box<types::PeerManager>,
    i2np: Box<types::InboundMessageHandler>,
    netdb: Box<types::NetworkDatabase>,
}

impl Router {
    /// Start the router.
    ///
    /// This returns a Future that must be polled in order to drive the Router.
    pub fn start(&mut self) -> impl Future<Item = (), Error = io::Error> {
        let mut inner = self.inner.lock().unwrap();
        let keys = inner.keys.clone();
        inner.comms.start(keys)
    }
}
