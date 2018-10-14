use futures::Future;
use std::sync::{Arc, RwLock};

use data::{Hash, RouterInfo, RouterSecretKeys};
use i2np::{DatabaseStoreData, Message, MessagePayload};
use netdb::netdb_engine;

mod builder;
mod config;
mod mock;
pub mod types;

pub use self::builder::Builder;
pub use self::config::Config;

pub struct MessageHandler {
    netdb: Arc<RwLock<types::NetworkDatabase>>,
}

impl MessageHandler {
    pub fn new(netdb: Arc<RwLock<types::NetworkDatabase>>) -> Self {
        MessageHandler { netdb }
    }
}

impl types::InboundMessageHandler for MessageHandler {
    fn handle(&self, from: Hash, msg: Message) {
        match msg.payload {
            MessagePayload::DatabaseStore(ds) => match ds.data {
                DatabaseStoreData::RI(ri) => {
                    self.netdb
                        .write()
                        .unwrap()
                        .store_router_info(ds.key, ri)
                        .expect("Failed to store RouterInfo");
                }
                DatabaseStoreData::LS(ls) => {
                    self.netdb
                        .write()
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
    ctx: Arc<Context>,
}

pub struct Context {
    keys: RouterSecretKeys,
    pub ri: Arc<RwLock<RouterInfo>>,
    netdb: Arc<RwLock<types::NetworkDatabase>>,
    pub comms: Arc<RwLock<types::CommSystem>>,
}

impl Router {
    /// Start the router.
    ///
    /// This returns a Future that must be polled in order to drive the Router.
    pub fn start(&mut self) -> impl Future<Item = (), Error = ()> {
        let keys = self.ctx.keys.clone();
        self.ctx
            .comms
            .write()
            .unwrap()
            .start(keys)
            .map_err(|e| {
                error!("CommSystem engine error: {}", e);
            }).join(netdb_engine(self.ctx.netdb.clone()))
            .map(|_| ())
    }
}
