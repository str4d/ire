//! The traits for the various router components.

use tokio_io::IoFuture;

use data::{Hash, RouterAddress, RouterSecretKeys};
use i2np::Message;

/// Manages the communication subsystem between peers, including connections,
/// listeners, transports, connection keys, etc.
pub trait CommSystem {
    /// Returns the addresses of the underlying transports.
    fn addresses(&self) -> Vec<RouterAddress>;

    /// Start the comm system.
    ///
    /// This returns a Future that must be polled in order to drive network
    /// communications.
    fn start(&mut self, rsk: RouterSecretKeys) -> IoFuture<()>;

    /// Send an I2NP message to a peer.
    ///
    /// Returns an Err giving back the message if it cannot be sent.
    fn send(&self, hash: Hash, msg: Message) -> Result<IoFuture<()>, (Hash, Message)>;
}
