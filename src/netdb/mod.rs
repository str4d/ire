//! The I2P network database.

use futures::{future, Future};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio_timer::sleep;

use data::{Hash, LeaseSet, RouterInfo, NET_ID};
use router::{
    config,
    types::{LookupError, NetworkDatabase, StoreError},
    Context,
};

pub mod reseed;

/// Maximum age of a local RouterInfo.
const ROUTER_INFO_EXPIRATION: u64 = 27 * 60 * 60;

/// Minimum seconds per engine cycle.
const ENGINE_DOWNTIME: u64 = 10;
/// If we know fewer than this many routers, we will reseed.
const MINIMUM_ROUTERS: usize = 50;

/// Performs network database maintenance operations.
struct Engine {
    ctx: Arc<Context>,
}

impl Engine {
    fn new(ctx: Arc<Context>) -> Self {
        Engine { ctx }
    }

    fn start_cycle(self) -> future::FutureResult<Self, ()> {
        trace!("Starting NetDB engine cycle");
        future::ok(self)
    }

    fn check_reseed(self) -> Box<Future<Item = Self, Error = ()> + Send> {
        let enabled = self
            .ctx
            .config
            .read()
            .unwrap()
            .get_bool(config::RESEED_ENABLE)
            .unwrap();
        if enabled && self.ctx.netdb.read().unwrap().known_routers() < MINIMUM_ROUTERS {
            // Reseed "synchronously" within the engine, as we can't do much without peers
            Box::new(reseed::HttpsReseeder::new(self.ctx.clone()).and_then(|()| future::ok(self)))
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

pub fn netdb_engine(ctx: Arc<Context>) -> Box<Future<Item = (), Error = ()> + Send> {
    Box::new(future::loop_fn(Engine::new(ctx), |engine| {
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

fn router_info_is_current(ri: &RouterInfo) -> Result<(), StoreError> {
    let published = ri.published.to_system_time();
    let now = SystemTime::now();

    if published < now - Duration::from_secs(ROUTER_INFO_EXPIRATION) {
        return Err(StoreError::Expired(now.duration_since(published).unwrap()));
    }

    // Allow RouterInfos published up to 2 minutes in the future, to handle clock drift.
    if published > now + Duration::from_secs(2 * 60) {
        return Err(StoreError::PublishedInFuture);
    }

    Ok(())
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
        ctx: Option<Arc<Context>>,
        key: &Hash,
        timeout_ms: u64,
    ) -> Box<Future<Item = RouterInfo, Error = LookupError> + Send + Sync> {
        match self.ri_ds.get(key) {
            Some(ri) => Box::new(future::ok(ri.clone())),
            None => Box::new(future::err(LookupError::NotFound)),
        }
    }

    fn lookup_lease_set(
        &mut self,
        ctx: Option<Arc<Context>>,
        key: &Hash,
        timeout_ms: u64,
        from_local_dest: Option<Hash>,
    ) -> Box<Future<Item = LeaseSet, Error = LookupError>> {
        match self.ls_ds.get(key) {
            Some(ls) => Box::new(future::ok(ls.clone())),
            None => Box::new(future::err(LookupError::NotFound)),
        }
    }

    fn store_router_info(
        &mut self,
        key: Hash,
        ri: RouterInfo,
    ) -> Result<Option<RouterInfo>, StoreError> {
        // Validate the RouterInfo
        if key != ri.router_id.hash() {
            return Err(StoreError::InvalidKey);
        }
        ri.verify()?;
        if ri
            .network_id()
            .map(|net_id| *net_id != *NET_ID)
            .unwrap_or(true)
        {
            return Err(StoreError::WrongNetwork);
        }
        router_info_is_current(&ri)?;

        debug!("Storing RouterInfo at key {}", key);
        Ok(self.ri_ds.insert(key, ri))
    }

    fn store_lease_set(&mut self, key: Hash, ls: LeaseSet) -> Result<Option<LeaseSet>, StoreError> {
        debug!("Storing LeaseSet at key {}", key);
        Ok(self.ls_ds.insert(key, ls))
    }
}

#[cfg(test)]
mod tests {
    use futures::Async;

    use super::LocalNetworkDatabase;
    use data::{Hash, RouterInfo, RouterSecretKeys};
    use router::types::{NetworkDatabase, StoreError};

    #[test]
    fn store_and_retrieve() {
        let mut netdb = LocalNetworkDatabase::new();

        let rsk = RouterSecretKeys::new();
        let mut ri = RouterInfo::new(rsk.rid);
        ri.sign(&rsk.signing_private_key);

        let key = ri.router_id.hash();

        assert_eq!(netdb.known_routers(), 0);

        // Storing with an invalid key should fail
        assert_eq!(
            netdb.store_router_info(Hash([0u8; 32]), ri.clone()),
            Err(StoreError::InvalidKey)
        );

        // Storing the new RouterInfo should return no data
        assert_eq!(netdb.store_router_info(key.clone(), ri.clone()), Ok(None));
        assert_eq!(netdb.known_routers(), 1);

        match netdb.lookup_router_info(None, &key, 100).poll() {
            Ok(Async::Ready(entry)) => assert_eq!(entry, ri),
            Ok(_) => panic!("Local lookup should complete immediately"),
            Err(e) => panic!("Unexpected error: {}", e),
        }
    }
}
