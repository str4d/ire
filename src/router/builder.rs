use std::io;
use std::sync::{Arc, Mutex};

use super::{
    mock,
    types::{CommSystem, InboundMessageHandler, NetworkDatabase},
    Config, Inner, MessageHandler, Router,
};
use data::{ReadError, RouterInfo, RouterSecretKeys};
use netdb::LocalNetworkDatabase;
use transport;

type CS<'a> = Box<Fn(Arc<InboundMessageHandler>) -> Box<CommSystem> + 'a>;

pub struct Builder<'a> {
    keys: Option<RouterSecretKeys>,
    ri_file: Option<String>,
    netdb: Option<Arc<Mutex<NetworkDatabase>>>,
    comms: Option<CS<'a>>,
}

impl<'a> Builder<'a> {
    /// Create a blank Builder.
    pub fn new() -> Self {
        Builder {
            keys: None,
            ri_file: None,
            netdb: None,
            comms: None,
        }
    }

    /// Create a Builder from the given Config.
    pub fn from_config(cfg: Config) -> Result<Self, ReadError> {
        let ntcp_addr = cfg.ntcp_addr;
        let ntcp2_addr = cfg.ntcp2_addr;
        let ntcp2_keyfile = cfg.ntcp2_keyfile;

        Ok(Builder::new()
            .router_keys(RouterSecretKeys::from_file(&cfg.router_keyfile)?)
            .router_info_file(cfg.ri_file)
            .comm_system(move |msg_handler| {
                Box::new(transport::Manager::new(
                    msg_handler,
                    ntcp_addr,
                    ntcp2_addr,
                    &ntcp2_keyfile,
                ))
            }))
    }

    pub fn router_keys(mut self, keys: RouterSecretKeys) -> Self {
        self.keys = Some(keys);
        self
    }

    pub fn router_info_file(mut self, ri_file: String) -> Self {
        self.ri_file = Some(ri_file);
        self
    }

    pub fn network_database(mut self, netdb: Arc<Mutex<NetworkDatabase>>) -> Self {
        self.netdb = Some(netdb);
        self
    }

    pub fn comm_system<CS>(mut self, comms: CS) -> Self
    where
        CS: Fn(Arc<InboundMessageHandler>) -> Box<CommSystem> + 'a,
    {
        self.comms = Some(Box::new(comms));
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

        let netdb = match self.netdb {
            Some(netdb) => netdb,
            None => Arc::new(Mutex::new(LocalNetworkDatabase::new())),
        };

        let msg_handler = Arc::new(MessageHandler::new(netdb.clone()));

        let comms = match self.comms {
            Some(comms) => comms(msg_handler),
            None => Box::new(mock::MockCommSystem::new()),
        };

        let mut ri = RouterInfo::new(keys.rid.clone());
        ri.set_addresses(comms.addresses());
        ri.sign(&keys.signing_private_key);
        ri.to_file(&ri_file)?;

        Ok(Router {
            inner: Arc::new(Mutex::new(Inner { keys, netdb, comms })),
        })
    }
}
