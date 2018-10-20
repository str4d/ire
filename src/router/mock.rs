//! Mock implementations of various router components.
//!
//! Each implementation keeps sufficient internal state as to ensure
//! self-consistency across its component's API.

use futures::future;
use std::sync::{Arc, RwLock};
use tokio_io::IoFuture;

use super::types::{CommSystem, InboundMessageHandler, OutboundMessageHandler};
use data::{Hash, RouterAddress, RouterInfo, RouterSecretKeys};
use i2np::Message;
use netdb::LocalNetworkDatabase;
use router::Context;

struct MockMessageHandler;

impl InboundMessageHandler for MockMessageHandler {
    fn handle(&self, from: Hash, msg: Message) {}
}

pub(super) struct MockCommSystem;

impl MockCommSystem {
    pub(super) fn new() -> Self {
        MockCommSystem {}
    }
}

impl OutboundMessageHandler for MockCommSystem {
    fn send(&self, _hash: Hash, _msg: Message) -> Result<IoFuture<()>, (Hash, Message)> {
        Ok(Box::new(future::ok(())))
    }
}

impl CommSystem for MockCommSystem {
    fn addresses(&self) -> Vec<RouterAddress> {
        vec![]
    }

    fn start(&mut self, _ctx: Arc<Context>) -> IoFuture<()> {
        Box::new(future::ok(()))
    }
}

pub fn mock_context() -> Arc<Context> {
    let keys = RouterSecretKeys::new();
    let mut ri = RouterInfo::new(keys.rid.clone());
    ri.sign(&keys.signing_private_key);

    Arc::new(Context {
        keys,
        ri: Arc::new(RwLock::new(ri)),
        netdb: Arc::new(RwLock::new(LocalNetworkDatabase::new())),
        comms: Arc::new(RwLock::new(MockCommSystem::new())),
        msg_handler: Arc::new(MockMessageHandler {}),
    })
}
