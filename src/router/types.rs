//! The traits for the various router components.

use futures::Future;
use tokio_io::IoFuture;

use data::{Hash, LeaseSet, RouterAddress, RouterInfo, RouterSecretKeys};
use i2np::Message;

pub trait OutboundMessageHandler {
    /// Send an I2NP message to a peer.
    ///
    /// Returns an Err giving back the message if it cannot be sent.
    fn send(&self, hash: Hash, msg: Message) -> Result<IoFuture<()>, (Hash, Message)>;
}

/// Manages the communication subsystem between peers, including connections,
/// listeners, transports, connection keys, etc.
pub trait CommSystem: OutboundMessageHandler {
    /// Returns the addresses of the underlying transports.
    fn addresses(&self) -> Vec<RouterAddress>;

    /// Start the comm system.
    ///
    /// This returns a Future that must be polled in order to drive network
    /// communications.
    fn start(&mut self, rsk: RouterSecretKeys) -> IoFuture<()>;
}

/// Defines the mechanism for interacting with I2P's network database.
pub trait NetworkDatabase {
    /// Finds the RouterInfo stored at the given key.
    fn lookup_router_info(
        &mut self,
        key: &Hash,
        timeout_ms: u64,
    ) -> Box<Future<Item = RouterInfo, Error = ()>>;

    /// Finds the LeaseSet stored at the given key. If not known locally, the LeaseSet is
    /// looked up using the client tunnels for `from_local_dest` if provided, or
    /// exploratory tunnels otherwise.
    fn lookup_lease_set(
        &mut self,
        key: &Hash,
        timeout_ms: u64,
        from_local_dest: Option<Hash>,
    ) -> Box<Future<Item = LeaseSet, Error = ()>>;

    /// Stores a RouterInfo locally.
    ///
    /// Returns the RouterInfo that was previously at this key.
    fn store_router_info(&mut self, key: Hash, ri: RouterInfo) -> Result<Option<RouterInfo>, ()>;

    /// Stores a LeaseSet locally.
    ///
    /// Returns the LeaseSet that was previously at this key.
    fn store_lease_set(&mut self, key: Hash, ls: LeaseSet) -> Result<Option<LeaseSet>, ()>;
}
