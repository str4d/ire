//! Mock implementations of various router components.
//!
//! Each implementation keeps sufficient internal state as to ensure
//! self-consistency across its component's API.

use config::Config;
use futures::{future, sync::mpsc, Future};
use std::sync::{Arc, Mutex, RwLock};
use tokio_io::IoFuture;

use super::types::{CommSystem, Distributor, DistributorResult};
use crate::data::{Hash, RouterAddress, RouterInfo, RouterSecretKeys};
use crate::i2np::Message;
use crate::netdb::{client::Client as NetDbClient, mock::MockNetDb};
use crate::router::Context;

#[derive(Clone)]
pub struct MockDistributor {
    pub received: Arc<Mutex<Vec<(Hash, Message)>>>,
}

impl MockDistributor {
    pub fn new() -> Self {
        MockDistributor {
            received: Arc::new(Mutex::new(vec![])),
        }
    }
}

impl Distributor for MockDistributor {
    fn handle(&self, from: Hash, msg: Message) -> DistributorResult {
        self.received.lock().unwrap().push((from, msg));
        Box::new(future::ok(()))
    }
}

pub(super) struct MockCommSystem;

impl MockCommSystem {
    pub(super) fn new() -> Self {
        MockCommSystem {}
    }
}

impl CommSystem for MockCommSystem {
    fn addresses(&self) -> Vec<RouterAddress> {
        vec![]
    }

    fn start(&mut self, _ctx: Arc<Context>) -> Box<dyn Future<Item = (), Error = ()> + Send> {
        Box::new(future::ok(()))
    }

    fn is_established(&self, _hash: &Hash) -> bool {
        false
    }

    fn send(
        &self,
        _peer: RouterInfo,
        _msg: Message,
    ) -> Result<IoFuture<()>, (RouterInfo, Message)> {
        Ok(Box::new(future::ok(())))
    }
}

pub fn mock_context() -> Arc<Context> {
    let (tx, _) = mpsc::unbounded();
    mock_context_with_netdb(NetDbClient::new(tx))
}

pub fn mock_context_and_netdb() -> (Arc<Context>, MockNetDb) {
    let (client_tx, client_rx) = mpsc::unbounded();
    let ctx = mock_context_with_netdb(NetDbClient::new(client_tx));
    let netdb = MockNetDb::new(ctx.clone(), client_rx);
    (ctx, netdb)
}

fn mock_context_with_netdb(netdb: NetDbClient) -> Arc<Context> {
    let keys = RouterSecretKeys::new();
    let mut ri = RouterInfo::new(keys.rid.clone());
    ri.sign(&keys.signing_private_key);

    Arc::new(Context {
        config: RwLock::new(Config::default()),
        keys,
        ri: Arc::new(RwLock::new(ri)),
        netdb,
        comms: Arc::new(RwLock::new(MockCommSystem::new())),
    })
}
