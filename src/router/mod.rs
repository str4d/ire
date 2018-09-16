use futures::Future;
use std::io;
use std::sync::{Arc, Mutex};

use data::RouterSecretKeys;

pub mod types;

/// An I2P router.
pub struct Router {
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    keys: RouterSecretKeys,
    comms: Box<types::CommSystem>,
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
