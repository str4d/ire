use futures::{
    future::{self, lazy},
    sync::mpsc,
    Future, Sink,
};
use std::sync::{Arc, RwLock};
use tokio_executor::spawn;
use tokio_io::IoFuture;

use crate::data::{Hash, RouterInfo, RouterSecretKeys};
use crate::i2np::{Message, MessagePayload};
use crate::netdb::{self, PendingTx};

mod builder;
pub mod config;
pub mod mock;
pub mod types;

pub use self::builder::Builder;
use self::config::Config;

pub(crate) type DistributorTx = mpsc::Sender<(Hash, Message)>;

#[derive(Clone)]
struct Distributor {
    netdb: DistributorTx,
}

impl Distributor {
    fn new(netdb: DistributorTx) -> Self {
        Distributor { netdb }
    }
}

impl types::Distributor for Distributor {
    fn handle(&self, from: Hash, msg: Message) -> types::DistributorResult {
        match msg.payload {
            MessagePayload::DatabaseStore(_)
            | MessagePayload::DatabaseLookup(_)
            | MessagePayload::DatabaseSearchReply(_) => {
                let f: types::DistributorResult =
                    Box::new(self.netdb.clone().send((from, msg)).map(|_| ()));
                f
            }
            _ => {
                debug!("Dropping unhandled message from {}:\n{}", from, msg);
                let f: types::DistributorResult = Box::new(future::ok(()));
                f
            }
        }
    }
}

/// An I2P router.
pub struct Router {
    ctx: Arc<Context>,
    netdb: Arc<RwLock<dyn types::NetworkDatabase>>,
    netdb_pending_tx: PendingTx,
    netdb_msg_handler: Option<netdb::MessageHandler>,
    netdb_client_handler: Option<netdb::ClientHandler>,
}

pub struct Context {
    pub config: RwLock<Config>,
    pub keys: RouterSecretKeys,
    pub ri: Arc<RwLock<RouterInfo>>,
    pub netdb: netdb::client::Client,
    pub comms: Arc<RwLock<dyn types::CommSystem>>,
}

impl Router {
    /// Returns a handle that can be used to interact with the router.
    pub fn handle(&self) -> Handle {
        Handle {
            ctx: self.ctx.clone(),
        }
    }

    /// Start the router.
    ///
    /// This returns a Future that must be polled in order to drive the Router.
    pub fn start(&mut self) -> impl Future<Item = (), Error = ()> {
        info!("Our router hash is {}", self.ctx.keys.rid.hash());

        let comms_engine = self.ctx.comms.write().unwrap().start(self.ctx.clone());
        let netdb_msg_handler = self
            .netdb_msg_handler
            .take()
            .expect("Can only call start() once");
        let netdb_client_handler = self
            .netdb_client_handler
            .take()
            .expect("Can only call start() once");
        let netdb_engine = netdb::Engine::new(
            self.netdb.clone(),
            self.ctx.clone(),
            self.netdb_pending_tx.clone(),
        );

        lazy(|| {
            // Start the transport system
            spawn(comms_engine);

            // Start the network database subsystems
            spawn(netdb_msg_handler);
            spawn(netdb_client_handler);

            // Start network database operations
            spawn(netdb_engine);

            Ok(())
        })
    }
}

#[derive(Clone)]
pub struct Handle {
    ctx: Arc<Context>,
}

impl Handle {
    pub fn hash(&self) -> Hash {
        self.ctx.keys.rid.hash()
    }

    pub fn send(
        &self,
        peer: RouterInfo,
        msg: Message,
    ) -> Result<IoFuture<()>, (RouterInfo, Message)> {
        self.ctx.comms.read().unwrap().send(peer, msg)
    }
}
