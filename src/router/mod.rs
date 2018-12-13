use futures::{future::lazy, sync::oneshot, Future};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use tokio_executor::spawn;

use crate::data::{Hash, RouterInfo, RouterSecretKeys};
use crate::i2np::{DatabaseSearchReply, DatabaseStoreData, Message, MessagePayload};
use crate::netdb::netdb_engine;

mod builder;
pub mod config;
pub mod mock;
pub mod types;

pub use self::builder::Builder;
use self::config::Config;

type PendingLookups = HashMap<(Hash, Hash), oneshot::Sender<DatabaseSearchReply>>;

pub struct MessageHandler {
    netdb: Arc<RwLock<dyn types::NetworkDatabase>>,
    pending_lookups: Mutex<PendingLookups>,
}

impl MessageHandler {
    pub fn new(netdb: Arc<RwLock<dyn types::NetworkDatabase>>) -> Self {
        MessageHandler {
            netdb,
            pending_lookups: Mutex::new(HashMap::new()),
        }
    }
}

impl types::MessageHandler for MessageHandler {
    fn register_lookup(&self, from: Hash, key: Hash, tx: oneshot::Sender<DatabaseSearchReply>) {
        self.pending_lookups.lock().unwrap().insert((from, key), tx);
    }

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
            MessagePayload::DatabaseSearchReply(dsr) => {
                if let Some(pending) = self
                    .pending_lookups
                    .lock()
                    .unwrap()
                    .remove(&(from.clone(), dsr.key.clone()))
                {
                    debug!("Received msg {} from {}:\n{}", msg.id, from, dsr);
                    if let Err(dsr) = pending.send(dsr) {
                        warn!(
                            "Lookup task timed out waiting for DatabaseSearchReply on {}",
                            dsr.key
                        );
                    }
                } else {
                    debug!(
                        "Received msg {} from {} with no pending lookup:\n{}",
                        msg.id, from, dsr
                    )
                }
            }
            _ => debug!("Received message from {}:\n{}", from, msg),
        }
    }
}

/// An I2P router.
pub struct Router {
    ctx: Arc<Context>,
}

pub struct Context {
    pub config: RwLock<Config>,
    pub keys: RouterSecretKeys,
    pub ri: Arc<RwLock<RouterInfo>>,
    pub netdb: Arc<RwLock<dyn types::NetworkDatabase>>,
    pub comms: Arc<RwLock<dyn types::CommSystem>>,
    pub msg_handler: Arc<dyn types::MessageHandler>,
}

impl Router {
    /// Start the router.
    ///
    /// This returns a Future that must be polled in order to drive the Router.
    pub fn start(&mut self) -> impl Future<Item = (), Error = ()> {
        info!("Our router hash is {}", self.ctx.keys.rid.hash());

        let comms_engine = self.ctx.comms.write().unwrap().start(self.ctx.clone());
        let netdb_engine = netdb_engine(self.ctx.clone());

        lazy(|| {
            // Start the transport system
            spawn(comms_engine);

            // Start network database operations
            spawn(netdb_engine);

            Ok(())
        })
    }
}
