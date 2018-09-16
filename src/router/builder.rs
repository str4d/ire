use std::io;
use std::sync::{Arc, Mutex};

use super::{mock, types::CommSystem, Config, Inner, Router};
use data::{RouterInfo, RouterSecretKeys};
use transport;

pub struct Builder {
    keys: Option<RouterSecretKeys>,
    ri_file: Option<String>,
    comms: Option<Box<CommSystem>>,
}

impl Builder {
    /// Create a blank Builder.
    pub fn new() -> Self {
        Builder {
            keys: None,
            ri_file: None,
            comms: None,
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

        let mut ri = RouterInfo::new(keys.rid.clone());
        ri.set_addresses(comms.addresses());
        ri.sign(&keys.signing_private_key);
        ri.to_file(&ri_file)?;

        Ok(Router {
            inner: Arc::new(Mutex::new(Inner { keys, comms })),
        })
    }
}
