//! Mock implementations of various router components.
//!
//! Each implementation keeps sufficient internal state as to ensure
//! self-consistency across its component's API.

use futures::future;
use tokio_io::IoFuture;

use super::types::{CommSystem, OutboundMessageHandler};
use data::{Hash, RouterAddress, RouterSecretKeys};
use i2np::Message;

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

    fn start(&mut self, _rsk: RouterSecretKeys) -> IoFuture<()> {
        Box::new(future::ok(()))
    }
}
