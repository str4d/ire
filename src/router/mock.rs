//! Mock implementations of various router components.
//!
//! Each implementation keeps sufficient internal state as to ensure
//! self-consistency across its component's API.

use config::Config;
use futures::{future, sync::oneshot, Future};
use std::sync::{Arc, Mutex, RwLock};
use tokio_io::IoFuture;

use super::types::{CommSystem, Distributor, DistributorResult, MessageHandler};
use crate::data::{Hash, RouterAddress, RouterInfo, RouterSecretKeys};
use crate::i2np::{DatabaseSearchReply, Message};
use crate::netdb::LocalNetworkDatabase;
use crate::router::Context;

struct MockMessageHandler;

impl MessageHandler for MockMessageHandler {
    fn register_lookup(&self, _from: Hash, _key: Hash, _tx: oneshot::Sender<DatabaseSearchReply>) {}
    fn handle(&self, _from: Hash, _msg: Message) {}
}

#[derive(Clone)]
pub(crate) struct MockDistributor {
    pub(crate) received: Arc<Mutex<Vec<(Hash, Message)>>>,
}

impl MockDistributor {
    pub(crate) fn new() -> Self {
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
    let keys = RouterSecretKeys::new();
    let mut ri = RouterInfo::new(keys.rid.clone());
    ri.sign(&keys.signing_private_key);

    Arc::new(Context {
        config: RwLock::new(Config::default()),
        keys,
        ri: Arc::new(RwLock::new(ri)),
        netdb: Arc::new(RwLock::new(LocalNetworkDatabase::new())),
        comms: Arc::new(RwLock::new(MockCommSystem::new())),
        msg_handler: Arc::new(MockMessageHandler {}),
    })
}
