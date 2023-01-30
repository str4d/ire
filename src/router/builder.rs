use ::config::{Config, ConfigError, File};
use futures::sync::mpsc;
use std::fmt;
use std::fs;
use std::io;
use std::sync::{Arc, RwLock};

use super::{types::CommSystem, Context, Distributor, Router};
use crate::data::{ReadError, RouterInfo, RouterSecretKeys};
use crate::netdb::{client::Client as NetDbClient, Engine as NetDbEngine};
use crate::router::config;
use crate::transport;
use crate::tunnel;

/// Builder errors
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Read(ReadError),
    Write(String),
}

#[cfg(not(tarpaulin_include))]
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
    comms: Option<Arc<RwLock<dyn CommSystem>>>,
}

impl Builder {
    /// Create a blank Builder.
    pub fn new() -> Self {
        Builder {
            cfg_file: None,
            keys: None,
            ri_file: None,
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

    pub fn comm_system(mut self, comms: Arc<RwLock<dyn CommSystem>>) -> Self {
        self.comms = Some(comms);
        self
    }

    /// Build a Router.
    pub fn build(self) -> Result<Router, Error> {
        let settings = Config::builder()
            .set_default(config::RESEED_ENABLE, true)
            .unwrap()
            .add_source(
                self.cfg_file
                    .as_deref()
                    .map(File::with_name)
                    .into_iter()
                    .collect::<Vec<_>>(),
            )
            .build()
            .unwrap();

        let keys = match self.keys {
            Some(keys) => keys,
            None => match settings.get_string(config::ROUTER_KEYFILE) {
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
                Err(e) => panic!("{}", e),
            },
        };

        // The goal of the next section is to build this subsystem graph:
        //
        //                 Incoming messages
        //                         |
        //                         v
        //           +------- Distributor -----+------------------------+
        //           |                         |                        |
        //           v                         v                        v
        //     netdb::Engine <-----> tunnel::Listener ------> tunnel::Participant
        //           |                         |                        |
        //           |                         |                        |
        //           +------> CommSystem <-----+------------------------+
        //                         |
        //                         v
        //                 Outgoing messages

        // Create channels between the various subsystems.
        let (netdb_pending_tx, netdb_pending_rx) = mpsc::channel(1024);
        let (netdb_ib_tx, netdb_ib_rx) = mpsc::channel(1024);
        let (netdb_client_tx, netdb_client_rx) = mpsc::unbounded();
        let (tunnel_build_ib_tx, tunnel_build_ib_rx) = mpsc::channel(1024);
        let (new_participating_tx, new_participating_rx) = mpsc::channel(1024);
        let (tunnel_data_ib_tx, tunnel_data_ib_rx) = mpsc::channel(1024);

        let distributor = Distributor::new(netdb_ib_tx, tunnel_build_ib_tx, tunnel_data_ib_tx);
        let netdb_client = NetDbClient::new(netdb_client_tx);

        let comms = match self.comms {
            Some(comms) => comms,
            None => Arc::new(RwLock::new(transport::Manager::from_config(
                &settings,
                distributor,
            ))),
        };

        let tunnel_participant = Some(tunnel::Participant::new(
            new_participating_rx,
            tunnel_data_ib_rx,
            comms.clone(),
        ));

        let mut ri = RouterInfo::new(keys.rid.clone());
        ri.set_addresses(comms.read().unwrap().addresses());
        ri.sign(&keys.signing_private_key);

        match settings.get_string(config::RI_FILE) {
            Ok(ri_file) => ri.to_file(&ri_file)?,
            Err(ConfigError::NotFound(key)) => warn!(
                "Config option {} not set, not writing RouterInfo to disk",
                key
            ),
            Err(e) => panic!("{}", e),
        }

        let ctx = Arc::new(Context {
            config: RwLock::new(settings),
            keys,
            ri: Arc::new(RwLock::new(ri)),
            netdb: netdb_client,
            comms,
        });

        let netdb_engine = Some(NetDbEngine::new(
            ctx.clone(),
            netdb_pending_tx,
            netdb_pending_rx,
            netdb_ib_rx,
            netdb_client_rx,
        ));

        let tunnel_listener = Some(tunnel::Listener::new(
            ctx.clone(),
            new_participating_tx,
            tunnel_build_ib_rx,
        ));

        Ok(Router {
            ctx,
            netdb_engine,
            tunnel_listener,
            tunnel_participant,
        })
    }
}
