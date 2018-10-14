//! The I2P network database.

use futures::{future, Future};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio_timer::sleep;

use data::{Hash, LeaseSet, RouterInfo};
use router::types::{NetworkDatabase, NetworkDatabaseError};

pub mod reseed;

/// Minimum seconds per engine cycle.
const ENGINE_DOWNTIME: u64 = 10;
/// If we know fewer than this many routers, we will reseed.
const MINIMUM_ROUTERS: usize = 50;

/// Performs network database maintenance operations.
struct Engine {
    db: Arc<RwLock<NetworkDatabase>>,
    reseeder: Option<reseed::HttpsReseeder>,
}

impl Engine {
    fn new(db: Arc<RwLock<NetworkDatabase>>) -> Self {
        Engine { db, reseeder: None }
    }

    fn start_cycle(self) -> future::FutureResult<Self, ()> {
        trace!("Starting NetDB engine cycle");
        future::ok(self)
    }

    fn check_reseed(self) -> Box<Future<Item = Self, Error = ()> + Send> {
        if self.reseeder.is_none() && self.db.read().unwrap().known_routers() < MINIMUM_ROUTERS {
            // Reseed "synchronously" within the engine, as we can't do much without peers
            Box::new(reseed::HttpsReseeder::new().and_then(|ris| {
                {
                    let mut db = self.db.write().unwrap();
                    for ri in ris {
                        db.store_router_info(ri.router_id.hash(), ri).unwrap();
                    }
                }
                future::ok(self)
            }))
        } else {
            Box::new(future::ok(self))
        }
    }

    fn finish_cycle(self) -> Box<Future<Item = (Self, bool), Error = ()> + Send> {
        trace!("Finished NetDB engine cycle");
        Box::new(
            sleep(Duration::from_secs(ENGINE_DOWNTIME))
                .map_err(|e| {
                    error!("NetDB timer error: {}", e);
                }).and_then(|_| future::ok((self, false))),
        )
    }
}

pub fn netdb_engine(db: Arc<RwLock<NetworkDatabase>>) -> Box<Future<Item = (), Error = ()> + Send> {
    Box::new(future::loop_fn(Engine::new(db), |engine| {
        engine
            .start_cycle()
            .and_then(|engine| engine.check_reseed())
            .and_then(|engine| engine.finish_cycle())
            .and_then(|(engine, done)| {
                if done {
                    Ok(future::Loop::Break(()))
                } else {
                    Ok(future::Loop::Continue(engine))
                }
            })
    }))
}

/// A NetworkDatabase that never publishes data to the network.
pub struct LocalNetworkDatabase {
    ri_ds: HashMap<Hash, RouterInfo>,
    ls_ds: HashMap<Hash, LeaseSet>,
}

impl LocalNetworkDatabase {
    pub(super) fn new() -> Self {
        LocalNetworkDatabase {
            ri_ds: HashMap::new(),
            ls_ds: HashMap::new(),
        }
    }
}

impl NetworkDatabase for LocalNetworkDatabase {
    fn known_routers(&self) -> usize {
        self.ri_ds.len()
    }

    fn lookup_router_info(
        &mut self,
        key: &Hash,
        timeout_ms: u64,
    ) -> Box<Future<Item = RouterInfo, Error = NetworkDatabaseError>> {
        match self.ri_ds.get(key) {
            Some(ri) => Box::new(future::ok(ri.clone())),
            None => Box::new(future::err(NetworkDatabaseError::NotFound)),
        }
    }

    fn lookup_lease_set(
        &mut self,
        key: &Hash,
        timeout_ms: u64,
        from_local_dest: Option<Hash>,
    ) -> Box<Future<Item = LeaseSet, Error = NetworkDatabaseError>> {
        match self.ls_ds.get(key) {
            Some(ls) => Box::new(future::ok(ls.clone())),
            None => Box::new(future::err(NetworkDatabaseError::NotFound)),
        }
    }

    fn store_router_info(
        &mut self,
        key: Hash,
        ri: RouterInfo,
    ) -> Result<Option<RouterInfo>, NetworkDatabaseError> {
        debug!(
            "Storing RouterInfo for peer {} at key {}",
            ri.router_id.hash(),
            key
        );
        Ok(self.ri_ds.insert(key, ri))
    }

    fn store_lease_set(
        &mut self,
        key: Hash,
        ls: LeaseSet,
    ) -> Result<Option<LeaseSet>, NetworkDatabaseError> {
        debug!("Storing LeaseSet at key {}", key);
        Ok(self.ls_ds.insert(key, ls))
    }
}

#[cfg(test)]
mod tests {
    use futures::Async;

    use super::LocalNetworkDatabase;
    use data::{Hash, RouterInfo, RouterSecretKeys};
    use router::types::NetworkDatabase;

    #[test]
    fn store_and_retrieve() {
        let mut netdb = LocalNetworkDatabase::new();

        let rsk = RouterSecretKeys::new();
        let mut ri = RouterInfo::new(rsk.rid);
        ri.sign(&rsk.signing_private_key);

        // TODO: replace fake key with real one
        let key = Hash([0u8; 32]);

        assert_eq!(netdb.known_routers(), 0);

        // Storing the new RouterInfo should return no data
        assert_eq!(netdb.store_router_info(key.clone(), ri.clone()), Ok(None));
        assert_eq!(netdb.known_routers(), 1);

        match netdb.lookup_router_info(&key, 100).poll() {
            Ok(Async::Ready(entry)) => assert_eq!(entry, ri),
            Ok(_) => panic!("Local lookup should complete immediately"),
            Err(e) => panic!("Unexpected error: {}", e),
        }
    }
}
