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
use crate::netdb;
use crate::tunnel;

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
    tunnel_acceptor: DistributorTx,
    tunnel_processor: DistributorTx,
}

impl Distributor {
    fn new(
        netdb: DistributorTx,
        tunnel_acceptor: DistributorTx,
        tunnel_processor: DistributorTx,
    ) -> Self {
        Distributor {
            netdb,
            tunnel_acceptor,
            tunnel_processor,
        }
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
            MessagePayload::TunnelData(_) | MessagePayload::TunnelGateway(_) => {
                let f: types::DistributorResult =
                    Box::new(self.tunnel_processor.clone().send((from, msg)).map(|_| ()));
                f
            }
            MessagePayload::TunnelBuild(_) | MessagePayload::VariableTunnelBuild(_) => {
                let f: types::DistributorResult =
                    Box::new(self.tunnel_acceptor.clone().send((from, msg)).map(|_| ()));
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
    netdb_engine: Option<netdb::Engine>,
    tunnel_listener: Option<tunnel::Listener>,
    tunnel_participant: Option<tunnel::Participant>,
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
        let netdb_engine = self
            .netdb_engine
            .take()
            .expect("Can only call start() once");

        let tunnel_listener = self
            .tunnel_listener
            .take()
            .expect("Can only call start() once");

        let tunnel_participant = self
            .tunnel_participant
            .take()
            .expect("Can only call start() once");

        lazy(|| {
            // Start the transport system
            spawn(comms_engine);

            // Start the TunnelBuildRequest listener subsystem
            spawn(tunnel_listener);

            // Start the tunnel participant subsystem
            spawn(tunnel_participant);

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
