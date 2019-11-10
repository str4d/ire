//! The traits for the various router components.

use futures::{sync::mpsc, Future};
use std::sync::Arc;
use tokio::io;

use super::Context;
use crate::data::{Hash, RouterAddress, RouterInfo};
use crate::i2np::Message;

type IoFuture<T> = Box<dyn Future<Item = T, Error = io::Error> + Send>;

pub type DistributorResult =
    Box<dyn Future<Item = (), Error = mpsc::SendError<(Hash, Message)>> + Send>;

pub trait Distributor: Clone + Send + Sync + 'static {
    fn handle(&self, from: Hash, msg: Message) -> DistributorResult;
}

/// Manages the communication subsystem between peers, including connections,
/// listeners, transports, connection keys, etc.
pub trait CommSystem: Send + Sync {
    /// Returns the addresses of the underlying transports.
    fn addresses(&self) -> Vec<RouterAddress>;

    /// Start the comm system.
    ///
    /// This returns a Future that must be polled in order to drive network
    /// communications.
    fn start(&mut self, ctx: Arc<Context>) -> Box<dyn Future<Item = (), Error = ()> + Send>;

    /// Returns true if there is an open session with the given peer.
    fn is_established(&self, hash: &Hash) -> bool;

    /// Send an I2NP message to a peer.
    ///
    /// Returns an Err giving back the message if it cannot be sent.
    fn send(&self, peer: RouterInfo, msg: Message) -> Result<IoFuture<()>, (RouterInfo, Message)>;
}
