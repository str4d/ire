use std::io;
use std::sync::{Arc, Mutex};

use super::{mock, types::CommSystem, Config, Inner, Router};
use data::RouterSecretKeys;
use transport;

pub struct Builder {
    keys: Option<RouterSecretKeys>,
    comms: Option<Box<CommSystem>>,
}

impl Builder {
    /// Create a blank Builder.
    pub fn new() -> Self {
        Builder {
            keys: None,
            comms: None,
        }
    }

    /// Create a Builder from the given Config.
    pub fn from_config(cfg: Config) -> io::Result<Self> {
        Ok(Builder::new()
            .router_keys(RouterSecretKeys::from_file(&cfg.router_keyfile)?)
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

    pub fn comm_system(mut self, comms: Box<CommSystem>) -> Self {
        self.comms = Some(comms);
        self
    }

    /// Build a Router.
    pub fn build(self) -> Router {
        let keys = match self.keys {
            Some(keys) => keys,
            None => RouterSecretKeys::new(),
        };

        let comms = match self.comms {
            Some(comms) => comms,
            None => Box::new(mock::MockCommSystem::new()),
        };

        Router {
            inner: Arc::new(Mutex::new(Inner { keys, comms })),
        }
    }
}
