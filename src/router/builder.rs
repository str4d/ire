use std::io;
use std::sync::{Arc, RwLock};

use super::{
    mock,
    types::{CommSystem, NetworkDatabase},
    Config, Context, MessageHandler, Router,
};
use data::{ReadError, RouterInfo, RouterSecretKeys};
use netdb::LocalNetworkDatabase;
use transport;

pub struct Builder {
    keys: Option<RouterSecretKeys>,
    ri_file: Option<String>,
    netdb: Option<Arc<RwLock<NetworkDatabase>>>,
    comms: Option<Arc<RwLock<CommSystem>>>,
}

impl Builder {
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
            .comm_system(Arc::new(RwLock::new(transport::Manager::new(
                ntcp_addr,
                ntcp2_addr,
                &ntcp2_keyfile,
            )))))
    }

    pub fn router_keys(mut self, keys: RouterSecretKeys) -> Self {
        self.keys = Some(keys);
        self
    }

    pub fn router_info_file(mut self, ri_file: String) -> Self {
        self.ri_file = Some(ri_file);
        self
    }

    pub fn network_database(mut self, netdb: Arc<RwLock<NetworkDatabase>>) -> Self {
        self.netdb = Some(netdb);
        self
    }

    pub fn comm_system(mut self, comms: Arc<RwLock<CommSystem>>) -> Self {
        self.comms = Some(comms);
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
            None => Arc::new(RwLock::new(LocalNetworkDatabase::new())),
        };

        let comms = match self.comms {
            Some(comms) => comms,
            None => Arc::new(RwLock::new(mock::MockCommSystem::new())),
        };

        let msg_handler = Arc::new(MessageHandler::new(netdb.clone()));

        let mut ri = RouterInfo::new(keys.rid.clone());
        ri.set_addresses(comms.read().unwrap().addresses());
        ri.sign(&keys.signing_private_key);
        ri.to_file(&ri_file)?;

        Ok(Router {
            ctx: Arc::new(Context {
                keys,
                ri: Arc::new(RwLock::new(ri)),
                netdb,
                comms,
                msg_handler,
            }),
        })
    }
}
