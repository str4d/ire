//! Mock implementations of various router components.
//!
//! Each implementation keeps sufficient internal state as to ensure
//! self-consistency across its component's API.

use futures;
use tokio_io::IoFuture;

use super::types::{CommSystem, InboundMessageHandler, NetworkDatabase, PeerManager};
use data::{Hash, RouterAddress, RouterSecretKeys};
use i2np::Message;

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

    fn start(&mut self, _rsk: RouterSecretKeys) -> IoFuture<()> {
        Box::new(futures::finished(()))
    }

    fn send(&self, _hash: Hash, _msg: Message) -> Result<IoFuture<()>, (Hash, Message)> {
        Ok(Box::new(futures::finished(())))
    }
}

pub(super) struct MockPeerManager;

impl MockPeerManager {
    pub(super) fn new() -> Self {
        MockPeerManager {}
    }
}

impl PeerManager for MockPeerManager {}

pub(super) struct MockInboundMessageHandler;

impl MockInboundMessageHandler {
    pub(super) fn new() -> Self {
        MockInboundMessageHandler {}
    }
}

impl InboundMessageHandler for MockInboundMessageHandler {}

pub(super) struct MockNetworkDatabase;

impl MockNetworkDatabase {
    pub(super) fn new() -> Self {
        MockNetworkDatabase {}
    }
}

impl NetworkDatabase for MockNetworkDatabase {}
