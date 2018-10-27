//! The traits for the various router components.

use futures::{sync::oneshot, Future};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;
use tokio_io::IoFuture;

use super::Context;
use crypto;
use data::{Hash, LeaseSet, RouterAddress, RouterInfo};
use i2np::{DatabaseSearchReply, Message};

pub trait InboundMessageHandler: Send + Sync {
    fn register_lookup(&self, key: Hash, tx: oneshot::Sender<DatabaseSearchReply>);

    fn handle(&self, from: Hash, msg: Message);
}

pub trait OutboundMessageHandler {
    /// Send an I2NP message to a peer.
    ///
    /// Returns an Err giving back the message if it cannot be sent.
    fn send(&self, peer: RouterInfo, msg: Message) -> Result<IoFuture<()>, (RouterInfo, Message)>;
}

/// Manages the communication subsystem between peers, including connections,
/// listeners, transports, connection keys, etc.
pub trait CommSystem: OutboundMessageHandler + Send + Sync {
    /// Returns the addresses of the underlying transports.
    fn addresses(&self) -> Vec<RouterAddress>;

    /// Start the comm system.
    ///
    /// This returns a Future that must be polled in order to drive network
    /// communications.
    fn start(&mut self, ctx: Arc<Context>) -> IoFuture<()>;
}

/// Network database lookup errors
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LookupError {
    NotFound,
    SendFailure,
    TimedOut,
    TimerFailure,
}

impl fmt::Display for LookupError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            LookupError::NotFound => "Key not found".fmt(f),
            LookupError::SendFailure => "Send failure".fmt(f),
            LookupError::TimedOut => "Lookup timed out".fmt(f),
            LookupError::TimerFailure => "Timer failure".fmt(f),
        }
    }
}

/// Network database store errors
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreError {
    Crypto(crypto::Error),
    Expired(Duration),
    InvalidKey,
    PublishedInFuture,
    WrongNetwork,
}

impl From<crypto::Error> for StoreError {
    fn from(e: crypto::Error) -> Self {
        StoreError::Crypto(e)
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            StoreError::Crypto(e) => e.fmt(f),
            StoreError::Expired(age) => {
                format!("Too old (published {} seconds ago)", age.as_secs()).fmt(f)
            }
            StoreError::InvalidKey => "Key does not match RouterInfo's RouterIdentity".fmt(f),
            StoreError::PublishedInFuture => "Published in future".fmt(f),
            StoreError::WrongNetwork => "Not in our network".fmt(f),
        }
    }
}

/// Defines the mechanism for interacting with I2P's network database.
pub trait NetworkDatabase: Send + Sync {
    /// Returns the number of RouterInfos that this database contains.
    fn known_routers(&self) -> usize;

    /// Finds the RouterInfo stored at the given key. If a Context is provided,
    /// a remote lookup will be performed if the key is not found locally.
    fn lookup_router_info(
        &mut self,
        ctx: Option<Arc<Context>>,
        key: &Hash,
        timeout_ms: u64,
        from_peer: Option<RouterInfo>,
    ) -> Box<Future<Item = RouterInfo, Error = LookupError> + Send>;

    /// Finds the LeaseSet stored at the given key. If not known locally, and a
    /// Context is provided, the LeaseSet is looked up using the client tunnels
    /// for `from_local_dest` if provided, or exploratory tunnels otherwise.
    fn lookup_lease_set(
        &mut self,
        ctx: Option<Arc<Context>>,
        key: &Hash,
        timeout_ms: u64,
        from_local_dest: Option<Hash>,
    ) -> Box<Future<Item = LeaseSet, Error = LookupError>>;

    /// Stores a RouterInfo locally.
    ///
    /// Returns the RouterInfo that was previously at this key.
    fn store_router_info(
        &mut self,
        key: Hash,
        ri: RouterInfo,
    ) -> Result<Option<RouterInfo>, StoreError>;

    /// Stores a LeaseSet locally.
    ///
    /// Returns the LeaseSet that was previously at this key.
    fn store_lease_set(&mut self, key: Hash, ls: LeaseSet) -> Result<Option<LeaseSet>, StoreError>;
}
