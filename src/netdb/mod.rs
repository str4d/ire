//! The I2P network database.

use chrono::offset::Utc;
use futures::{future, sync::oneshot, Async, Future};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio_timer::{sleep, Delay};

use data::{Hash, LeaseSet, RouterInfo, NET_ID};
use i2np::DatabaseLookupType;
use router::{
    config,
    types::{LookupError, NetworkDatabase, StoreError},
    Context,
};

mod lookup;
pub mod reseed;

/// Maximum age of a local RouterInfo.
const ROUTER_INFO_EXPIRATION: u64 = 27 * 60 * 60;

/// Minimum seconds per engine cycle.
const ENGINE_DOWNTIME: u64 = 10;
/// Interval on which we expire RouterInfos.
const EXPIRE_RI_INTERVAL: u64 = 5 * 60;
/// Interval on which we expire LeaseSets.
const EXPIRE_LS_INTERVAL: u64 = 60;
/// If we know fewer than this many routers, we will reseed.
const MINIMUM_ROUTERS: usize = 50;
/// If we know fewer than this many routers, we won't expire RouterInfos.
const KEEP_ROUTERS: usize = 150;

/// Performs network database maintenance operations.
struct Engine {
    ctx: Arc<Context>,
    expire_ri_timer: Delay,
    expire_ls_timer: Delay,
}

impl Engine {
    fn new(ctx: Arc<Context>) -> Self {
        Engine {
            ctx,
            expire_ri_timer: sleep(Duration::from_secs(EXPIRE_RI_INTERVAL)),
            expire_ls_timer: sleep(Duration::from_secs(EXPIRE_LS_INTERVAL)),
        }
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

    fn expire_router_infos(mut self) -> Box<Future<Item = Self, Error = ()> + Send> {
        if let Ok(Async::Ready(())) = self.expire_ri_timer.poll() {
            // Expire RouterInfos
            if self.ctx.netdb.read().unwrap().known_routers() >= KEEP_ROUTERS {
                self.ctx
                    .netdb
                    .write()
                    .unwrap()
                    .expire_router_infos(Some(self.ctx.clone()));
            }
            // Reset timer
            self.expire_ri_timer = sleep(Duration::from_secs(EXPIRE_RI_INTERVAL));
        }
        Box::new(future::ok(self))
    }

    fn expire_lease_sets(mut self) -> Box<Future<Item = Self, Error = ()> + Send> {
        if let Ok(Async::Ready(())) = self.expire_ls_timer.poll() {
            // Expire LeaseSets
            self.ctx.netdb.write().unwrap().expire_lease_sets();
            // Reset timer
            self.expire_ls_timer = sleep(Duration::from_secs(EXPIRE_LS_INTERVAL));
        }
        Box::new(future::ok(self))
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
            .and_then(|engine| engine.expire_router_infos())
            .and_then(|engine| engine.expire_lease_sets())
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

fn create_routing_key(key: &Hash) -> Hash {
    let mut data = [0u8; 40];
    data[0..32].copy_from_slice(&key.0);
    data[32..40].copy_from_slice(Utc::now().format("%Y%m%d").to_string().as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(Sha256::digest(&data).as_slice());
    Hash(out)
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct XorMetric([u8; 32]);

impl XorMetric {
    fn for_hash(hash: &Hash, key: &Hash) -> Self {
        let mut metric = hash.clone();
        metric.xor(key);
        XorMetric(metric.0)
    }
}

type PendingLookup<T> = HashMap<Hash, Vec<oneshot::Sender<T>>>;

/// A NetworkDatabase that never publishes data to the network.
pub struct LocalNetworkDatabase {
    ri_ds: HashMap<Hash, RouterInfo>,
    ls_ds: HashMap<Hash, LeaseSet>,
    pending_ri: PendingLookup<RouterInfo>,
    pending_ls: PendingLookup<LeaseSet>,
}

impl LocalNetworkDatabase {
    pub(super) fn new() -> Self {
        LocalNetworkDatabase {
            ri_ds: HashMap::new(),
            ls_ds: HashMap::new(),
            pending_ri: HashMap::new(),
            pending_ls: HashMap::new(),
        }
    }

    fn select_closest_ff(&self, key: &Hash) -> Option<RouterInfo> {
        let key = create_routing_key(key);
        self.ri_ds
            .values()
            .filter(|ri| ri.is_floodfill())
            .min_by_key(|ri| XorMetric::for_hash(&ri.router_id.hash(), &key))
            .cloned()
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
        from_peer: Option<RouterInfo>,
    ) -> Box<Future<Item = RouterInfo, Error = LookupError> + Send> {
        // First look for it locally, either available or pending
        let local: Option<Box<Future<Item = RouterInfo, Error = LookupError> + Send>> =
            match self.ri_ds.get(key) {
                Some(ri) => Some(Box::new(future::ok(ri.clone()))),
                None => match self.pending_ri.get_mut(key) {
                    Some(ref mut pending) => {
                        // There's a pending lookup; register to receive the result
                        let (tx, rx) = oneshot::channel();
                        pending.push(tx);
                        Some(Box::new(rx.map_err(|_| LookupError::TimedOut)))
                    }
                    None => None,
                },
            };

        match local {
            Some(f) => f,
            None => if let Some(ctx) = ctx {
                // TODO: Handle case where we don't know any floodfills
                match from_peer.or_else(|| self.select_closest_ff(key)) {
                    Some(ff) => lookup::lookup_db_entry(
                        ctx,
                        key.clone(),
                        DatabaseLookupType::RouterInfo,
                        ff,
                        &mut self.pending_ri,
                        timeout_ms,
                    ),
                    None => Box::new(future::err(LookupError::NotFound)),
                }
            } else {
                Box::new(future::err(LookupError::NotFound))
            },
        }
    }

    fn lookup_lease_set(
        &mut self,
        ctx: Option<Arc<Context>>,
        key: &Hash,
        timeout_ms: u64,
        from_local_dest: Option<Hash>,
    ) -> Box<Future<Item = LeaseSet, Error = LookupError>> {
        // First look for it locally, either available or pending
        let local: Option<Box<Future<Item = LeaseSet, Error = LookupError>>> =
            match self.ls_ds.get(key) {
                Some(ls) => Some(Box::new(future::ok(ls.clone()))),
                None => match self.pending_ls.get_mut(key) {
                    Some(ref mut pending) => {
                        // There's a pending lookup; register to receive the result
                        let (tx, rx) = oneshot::channel();
                        pending.push(tx);
                        Some(Box::new(rx.map_err(|_| LookupError::TimedOut)))
                    }
                    None => None,
                },
            };

        match local {
            Some(f) => f,
            None => if let Some(ctx) = ctx {
                // TODO: Handle case where we don't know any floodfills
                // TODO: Handle from_local_dest case
                match self.select_closest_ff(key) {
                    Some(ff) => lookup::lookup_db_entry(
                        ctx,
                        key.clone(),
                        DatabaseLookupType::LeaseSet,
                        ff,
                        &mut self.pending_ls,
                        timeout_ms,
                    ),
                    None => Box::new(future::err(LookupError::NotFound)),
                }
            } else {
                Box::new(future::err(LookupError::NotFound))
            },
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

        // If anyone was waiting on this RouterInfo, notify them
        if let Some(pending) = self.pending_ri.remove(&key) {
            for p in pending {
                if p.send(ri.clone()).is_err() {
                    warn!("Lookup task timed out waiting for RouterInfo at {}", key);
                }
            }
        }

        debug!("Storing RouterInfo at key {}", key);
        Ok(self.ri_ds.insert(key, ri))
    }

    fn store_lease_set(&mut self, key: Hash, ls: LeaseSet) -> Result<Option<LeaseSet>, StoreError> {
        // If anyone was waiting on this LeaseSet, notify them
        if let Some(pending) = self.pending_ls.remove(&key) {
            for p in pending {
                if p.send(ls.clone()).is_err() {
                    warn!("Lookup task timed out waiting for LeaseSet at {}", key);
                }
            }
        }

        debug!("Storing LeaseSet at key {}", key);
        Ok(self.ls_ds.insert(key, ls))
    }

    fn expire_router_infos(&mut self, ctx: Option<Arc<Context>>) {
        let comms = ctx.as_ref().map(|ctx| ctx.comms.read().unwrap());

        let before = self.ri_ds.len();
        self.ri_ds.retain(|_, ri| {
            // Don't expire RIs for peers we are connected to.
            if let Some(comms) = comms.as_ref() {
                if comms.is_established(&ri.router_id.hash()) {
                    return true;
                }
            }

            router_info_is_current(ri).is_ok()
        });
        let expired = before - self.ri_ds.len();
        if expired > 0 {
            debug!("Expired {} RouterInfos", expired);
        }
    }

    fn expire_lease_sets(&mut self) {
        let before = self.ls_ds.len();
        self.ls_ds.retain(|_, ls| ls.is_current());
        let expired = before - self.ls_ds.len();
        if expired > 0 {
            debug!("Expired {} LeaseSets", expired);
        }
    }
}

#[cfg(test)]
mod tests {
    use futures::Async;
    use std::time::{Duration, SystemTime};

    use super::{router_info_is_current, LocalNetworkDatabase, XorMetric, ROUTER_INFO_EXPIRATION};
    use crypto;
    use data::{Hash, I2PDate, RouterInfo, RouterSecretKeys, OPT_NET_ID};
    use router::types::{NetworkDatabase, StoreError};

    #[test]
    fn xor_metric() {
        let key_min = Hash([0; 32]);
        let key_max = Hash([0xff; 32]);

        assert_eq!(
            XorMetric::for_hash(&key_min, &key_min),
            XorMetric::for_hash(&key_max, &key_max)
        );

        let hash1 = Hash([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ]);
        let hash2 = Hash([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 2,
        ]);
        let hash1le = Hash([
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ]);

        assert!(XorMetric::for_hash(&key_min, &key_min) < XorMetric::for_hash(&hash1, &key_min));
        assert!(XorMetric::for_hash(&hash1, &key_min) < XorMetric::for_hash(&hash2, &key_min));
        assert!(XorMetric::for_hash(&hash1, &key_min) < XorMetric::for_hash(&hash1le, &key_min));

        assert!(XorMetric::for_hash(&key_max, &key_max) < XorMetric::for_hash(&hash1, &key_max));
        assert!(XorMetric::for_hash(&hash1, &key_max) > XorMetric::for_hash(&hash2, &key_max));
        assert!(XorMetric::for_hash(&hash1, &key_max) > XorMetric::for_hash(&hash1le, &key_max));
    }

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

        // Storing a RouterInfo modified after signing should fail
        let old_netid = ri.options.0.insert(OPT_NET_ID.clone(), "0".into()).unwrap();
        assert_eq!(
            netdb.store_router_info(key.clone(), ri.clone()),
            Err(StoreError::Crypto(crypto::Error::InvalidSignature))
        );
        ri.sign(&rsk.signing_private_key);

        // Storing with a different netId should fail
        assert_eq!(
            netdb.store_router_info(key.clone(), ri.clone()),
            Err(StoreError::WrongNetwork)
        );
        ri.options.0.insert(OPT_NET_ID.clone(), old_netid);
        ri.sign(&rsk.signing_private_key);

        // Storing the new RouterInfo should return no data
        assert_eq!(netdb.store_router_info(key.clone(), ri.clone()), Ok(None));
        assert_eq!(netdb.known_routers(), 1);

        match netdb.lookup_router_info(None, &key, 100, None).poll() {
            Ok(Async::Ready(entry)) => assert_eq!(entry, ri),
            Ok(_) => panic!("Local lookup should complete immediately"),
            Err(e) => panic!("Unexpected error: {}", e),
        }
    }

    #[test]
    fn ri_expiry() {
        let rsk = RouterSecretKeys::new();
        let mut ri = RouterInfo::new(rsk.rid);
        assert_eq!(router_info_is_current(&ri), Ok(()));

        // Expire the RouterInfo
        ri.published = I2PDate::from_system_time(
            SystemTime::now() - Duration::from_secs(ROUTER_INFO_EXPIRATION + 100),
        );
        match router_info_is_current(&ri) {
            Ok(()) => panic!("RouterInfo should have expired"),
            Err(StoreError::Expired(_)) => (),
            Err(e) => panic!("Unexpected error: {}", e),
        }

        // Create it in the future
        ri.published = I2PDate::from_system_time(
            SystemTime::now() + Duration::from_secs(ROUTER_INFO_EXPIRATION + 100),
        );
        assert_eq!(
            router_info_is_current(&ri),
            Err(StoreError::PublishedInFuture)
        );
    }
}
