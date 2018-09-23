use std::io;
use std::sync::{Arc, Mutex};

use super::{
    mock,
    types::{CommSystem, InboundMessageHandler, NetworkDatabase, PeerManager},
    Config, Inner, Router, RouterState,
};
use data::{RouterInfo, RouterSecretKeys};
use transport;

pub struct Builder {
    keys: Option<RouterSecretKeys>,
    ri_file: Option<String>,
    comms: Option<Box<CommSystem>>,
    peers: Option<Box<PeerManager>>,
    i2np: Option<Box<InboundMessageHandler>>,
    netdb: Option<Box<NetworkDatabase>>,
}

impl Builder {
    /// Create a blank Builder.
    pub fn new() -> Self {
        Builder {
            keys: None,
            ri_file: None,
            comms: None,
            peers: None,
            i2np: None,
            netdb: None,
        }
    }

    /// Create a Builder from the given Config.
    pub fn from_config(cfg: Config) -> io::Result<Self> {
        Ok(Builder::new()
            .router_keys(RouterSecretKeys::from_file(&cfg.router_keyfile)?)
            .router_info_file(cfg.ri_file)
            .comm_system(Box::new(transport::Manager::new(
                cfg.ntcp_addr,
                cfg.ntcp2_addr,
                &cfg.ntcp2_keyfile,
            ))))
    }

    pub fn router_keys(mut self, keys: RouterSecretKeys) -> Self {
        self.keys = Some(keys);
        self
    }

    pub fn router_info_file(mut self, ri_file: String) -> Self {
        self.ri_file = Some(ri_file);
        self
    }

    pub fn comm_system(mut self, comms: Box<CommSystem>) -> Self {
        self.comms = Some(comms);
        self
    }

    pub fn peer_manager(mut self, peers: Box<PeerManager>) -> Self {
        self.peers = Some(peers);
        self
    }

    pub fn i2np_handler(mut self, i2np: Box<InboundMessageHandler>) -> Self {
        self.i2np = Some(i2np);
        self
    }

    pub fn network_database(mut self, netdb: Box<NetworkDatabase>) -> Self {
        self.netdb = Some(netdb);
        self
    }

    /// Build a Router.
    pub fn build(self) -> io::Result<Router> {
        let keys = match self.keys {
            Some(keys) => keys,
            None => RouterSecretKeys::new(),
        };

        let ri_file = match self.ri_file {
            Some(ri_file) => ri_file,
            None => panic!("Must set location to store router.info"),
        };

        let comms = match self.comms {
            Some(comms) => comms,
            None => Box::new(mock::MockCommSystem::new()),
        };

        let peers = match self.peers {
            Some(peers) => peers,
            None => Box::new(mock::MockPeerManager::new()),
        };

        let i2np = match self.i2np {
            Some(i2np) => i2np,
            None => Box::new(mock::MockInboundMessageHandler::new()),
        };

        let netdb = match self.netdb {
            Some(netdb) => netdb,
            None => Box::new(mock::MockNetworkDatabase::new()),
        };

        let mut ri = RouterInfo::new(keys.rid.clone());
        ri.set_addresses(comms.addresses());
        ri.sign(&keys.signing_private_key);
        ri.to_file(&ri_file)?;

        Ok(Router {
            inner: Arc::new(Mutex::new(Inner {
                state: RouterState::Stopped,
                keys,
                comms,
                peers,
                i2np,
                netdb,
            })),
        })
    }
}
