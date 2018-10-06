//! The I2P network database.

use futures::{future, Future};
use std::collections::HashMap;

use data::{Hash, LeaseSet, RouterInfo};
use router::types::NetworkDatabase;

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
    fn lookup_router_info(
        &mut self,
        key: &Hash,
        timeout_ms: u64,
    ) -> Box<Future<Item = RouterInfo, Error = ()>> {
        match self.ri_ds.get(key) {
            Some(ri) => Box::new(future::ok(ri.clone())),
            None => Box::new(future::err(())),
        }
    }

    fn lookup_lease_set(
        &mut self,
        key: &Hash,
        timeout_ms: u64,
        from_local_dest: Option<Hash>,
    ) -> Box<Future<Item = LeaseSet, Error = ()>> {
        match self.ls_ds.get(key) {
            Some(ls) => Box::new(future::ok(ls.clone())),
            None => Box::new(future::err(())),
        }
    }

    fn store_router_info(&mut self, key: Hash, ri: RouterInfo) -> Result<Option<RouterInfo>, ()> {
        debug!(
            "Storing RouterInfo for peer {} at key {}",
            ri.router_id.hash(),
            key
        );
        Ok(self.ri_ds.insert(key, ri))
    }

    fn store_lease_set(&mut self, key: Hash, ls: LeaseSet) -> Result<Option<LeaseSet>, ()> {
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

        // Storing the new RouterInfo should return no data
        assert_eq!(netdb.store_router_info(key.clone(), ri.clone()), Ok(None));

        match netdb.lookup_router_info(&key, 100).poll() {
            Ok(Async::Ready(entry)) => assert_eq!(entry, ri),
            Ok(_) => panic!("Local lookup should complete immediately"),
            Err(_) => panic!("Error while looking up RouterInfo"),
        }
    }
}
