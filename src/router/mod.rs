use futures::Future;
use std::io;
use std::sync::{Arc, Mutex};

use data::{Hash, RouterSecretKeys};
use i2np::Message;

mod builder;
mod config;
mod mock;
pub mod types;

pub use self::builder::Builder;
pub use self::config::Config;

pub struct MessageHandler;

impl MessageHandler {
    pub fn new() -> Self {
        MessageHandler {}
    }
}

impl types::InboundMessageHandler for MessageHandler {
    fn handle(&self, from: Hash, msg: Message) {
        match msg.payload {
            _ => debug!("Received message from {}: {:?}", from, msg),
        }
    }
}

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
