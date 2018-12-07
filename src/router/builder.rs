use ::config::{Config, ConfigError, File};
use std::fmt;
use std::fs;
use std::io;
use std::sync::{Arc, RwLock};

use super::{
    types::{CommSystem, NetworkDatabase},
    Context, MessageHandler, Router,
};
use crate::data::{ReadError, RouterInfo, RouterSecretKeys};
use crate::netdb::LocalNetworkDatabase;
use crate::router::config;
use crate::transport;

/// Builder errors
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Read(ReadError),
    Write(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Read(e) => format!("{}", e).fmt(f),
            Error::Write(e) => e.fmt(f),
        }
    }
}

impl From<ReadError> for Error {
    fn from(e: ReadError) -> Self {
        Error::Read(e)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Write(format!("{}", e))
    }
}

pub struct Builder {
    cfg_file: Option<String>,
    keys: Option<RouterSecretKeys>,
    ri_file: Option<String>,
    netdb: Option<Arc<RwLock<NetworkDatabase>>>,
    comms: Option<Arc<RwLock<CommSystem>>>,
}

impl Builder {
    /// Create a blank Builder.
    pub fn new() -> Self {
        Builder {
            cfg_file: None,
            keys: None,
            ri_file: None,
            netdb: None,
            comms: None,
        }
    }

    pub fn config_file(mut self, cfg_file: String) -> Self {
        self.cfg_file = Some(cfg_file);
        self
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
    pub fn build(self) -> Result<Router, Error> {
        let mut settings = Config::default();

        // Default config options
        settings.set_default(config::RESEED_ENABLE, true).unwrap();

        if let Some(ref cfg_file) = self.cfg_file {
            settings.merge(File::with_name(&cfg_file)).unwrap();
        }

        let keys = match self.keys {
            Some(keys) => keys,
            None => match settings.get_str(config::ROUTER_KEYFILE) {
                // Check if the keyfile exists
                Ok(keyfile) => match fs::metadata(&keyfile) {
                    Ok(_) => RouterSecretKeys::from_file(&keyfile)?,
                    Err(_) => {
                        // We have a keyfile that doesn't exist, so create it
                        info!("Writing new router keys to {}", keyfile);
                        let keys = RouterSecretKeys::new();
                        keys.to_file(&keyfile)?;
                        keys
                    }
                },
                Err(ConfigError::NotFound(key)) => {
                    info!(
                        "Config option {} not set, creating ephemeral router keys",
                        key
                    );
                    RouterSecretKeys::new()
                }
                Err(e) => panic!(e),
            },
        };

        let netdb = match self.netdb {
            Some(netdb) => netdb,
            None => Arc::new(RwLock::new(LocalNetworkDatabase::new())),
        };

        let comms = match self.comms {
            Some(comms) => comms,
            None => Arc::new(RwLock::new(transport::Manager::from_config(&settings))),
        };

        let msg_handler = Arc::new(MessageHandler::new(netdb.clone()));

        let mut ri = RouterInfo::new(keys.rid.clone());
        ri.set_addresses(comms.read().unwrap().addresses());
        ri.sign(&keys.signing_private_key);

        match settings.get_str(config::RI_FILE) {
            Ok(ri_file) => ri.to_file(&ri_file)?,
            Err(ConfigError::NotFound(key)) => warn!(
                "Config option {} not set, not writing RouterInfo to disk",
                key
            ),
            Err(e) => panic!(e),
        }

        Ok(Router {
            ctx: Arc::new(Context {
                config: RwLock::new(settings),
                keys,
                ri: Arc::new(RwLock::new(ri)),
                netdb,
                comms,
                msg_handler,
            }),
        })
    }
}
