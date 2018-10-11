use futures::Future;
use std::sync::{Arc, Mutex};

use data::{Hash, RouterSecretKeys};
use i2np::{DatabaseStoreData, Message, MessagePayload};
use netdb::netdb_engine;

mod builder;
mod config;
mod mock;
pub mod types;

pub use self::builder::Builder;
pub use self::config::Config;

pub struct MessageHandler {
    netdb: Arc<Mutex<types::NetworkDatabase>>,
}

impl MessageHandler {
    pub fn new(netdb: Arc<Mutex<types::NetworkDatabase>>) -> Self {
        MessageHandler { netdb }
    }
}

impl types::InboundMessageHandler for MessageHandler {
    fn handle(&self, from: Hash, msg: Message) {
        match msg.payload {
            MessagePayload::DatabaseStore(ds) => match ds.data {
                DatabaseStoreData::RI(ri) => {
                    self.netdb
                        .lock()
                        .unwrap()
                        .store_router_info(ds.key, ri)
                        .expect("Failed to store RouterInfo");
                }
                DatabaseStoreData::LS(ls) => {
                    self.netdb
                        .lock()
                        .unwrap()
                        .store_lease_set(ds.key, ls)
                        .expect("Failed to store LeaseSet");
                }
            },
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
    netdb: Arc<Mutex<types::NetworkDatabase>>,
    comms: Box<types::CommSystem>,
}

impl Router {
    /// Start the router.
    ///
    /// This returns a Future that must be polled in order to drive the Router.
    pub fn start(&mut self) -> impl Future<Item = (), Error = ()> {
        let mut inner = self.inner.lock().unwrap();
        let keys = inner.keys.clone();
        inner
            .comms
            .start(keys)
            .map_err(|e| {
                error!("CommSystem engine error: {}", e);
            }).join(netdb_engine(inner.netdb.clone()))
            .map(|_| ())
    }
}
