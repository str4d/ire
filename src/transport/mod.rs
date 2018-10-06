//! Transports used for point-to-point communication between I2P routers.

use futures::{stream::Select, sync::mpsc, Async, Future, Poll, Sink, StartSend, Stream};
use std::io;
use std::iter::once;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio_io::IoFuture;

use crypto::dh::DHSessionKeyBuilder;
use data::{Hash, RouterAddress, RouterSecretKeys};
use i2np::Message;
use router::types::{CommSystem, InboundMessageHandler, OutboundMessageHandler};

pub mod ntcp;
pub mod ntcp2;
mod session;

/// Shorthand for the transmit half of a Transport-bound message channel.
type MessageTx = mpsc::UnboundedSender<(Hash, Message)>;

/// Shorthand for the receive half of a Transport-bound message channel.
type MessageRx = mpsc::UnboundedReceiver<(Hash, Message)>;

/// Shorthand for the transmit half of a Transport-bound timestamp channel.
type TimestampTx = mpsc::UnboundedSender<(Hash, u32)>;

/// Shorthand for the receive half of a Transport-bound timestamp channel.
type TimestampRx = mpsc::UnboundedReceiver<(Hash, u32)>;

/// A reference to a transport, that can be used to send messages and
/// timestamps to other routers (if they are reachable via this transport).
#[derive(Clone)]
pub struct Handle {
    message: MessageTx,
    timestamp: TimestampTx,
}

impl Handle {
    pub fn send(&self, hash: Hash, msg: Message) -> io::Result<()> {
        self.message
            .unbounded_send((hash, msg))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    pub fn timestamp(&self, hash: Hash, ts: u32) -> io::Result<()> {
        self.timestamp
            .unbounded_send((hash, ts))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }
}

/// A bid from a transport indicating how much it thinks it will "cost" to
/// send a particular message.
struct Bid {
    bid: u32,
    handle: Handle,
}

impl Sink for Bid {
    type SinkItem = (Hash, Message);
    type SinkError = ();

    fn start_send(
        &mut self,
        message: Self::SinkItem,
    ) -> StartSend<Self::SinkItem, Self::SinkError> {
        self.handle.message.start_send(message).map_err(|_| ())
    }

    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        self.handle.message.poll_complete().map_err(|_| ())
    }
}

/// Coordinates the sending and receiving of frames over the various supported
/// transports.
pub struct Manager {
    ntcp: ntcp::Manager,
    ntcp2: ntcp2::Manager,
    engine: Option<Engine>,
}

pub struct Engine {
    engines: Select<ntcp::Engine, ntcp2::Engine>,
    msg_handler: Arc<InboundMessageHandler>,
}

trait Transport {
    fn bid(&self, hash: &Hash, msg_size: usize) -> Option<Bid>;
}

impl Manager {
    pub fn new(
        msg_handler: Arc<InboundMessageHandler>,
        ntcp_addr: SocketAddr,
        ntcp2_addr: SocketAddr,
        ntcp2_keyfile: &str,
    ) -> Self {
        let (ntcp_manager, ntcp_engine) = ntcp::Manager::new(ntcp_addr);
        let (ntcp2_manager, ntcp2_engine) =
            match ntcp2::Manager::from_file(ntcp2_addr, ntcp2_keyfile) {
                Ok(ret) => ret,
                Err(_) => {
                    let (ntcp2_manager, ntcp2_engine) = ntcp2::Manager::new(ntcp2_addr);
                    ntcp2_manager.to_file(ntcp2_keyfile).unwrap();
                    (ntcp2_manager, ntcp2_engine)
                }
            };
        Manager {
            ntcp: ntcp_manager,
            ntcp2: ntcp2_manager,
            engine: Some(Engine {
                engines: ntcp_engine.select(ntcp2_engine),
                msg_handler,
            }),
        }
    }
}

impl OutboundMessageHandler for Manager {
    /// Send an I2NP message to a peer over one of our transports.
    ///
    /// Returns an Err giving back the message if it cannot be sent over any of
    /// our transports.
    fn send(&self, hash: Hash, msg: Message) -> Result<IoFuture<()>, (Hash, Message)> {
        match once(self.ntcp.bid(&hash, msg.size()))
            .chain(once(self.ntcp2.bid(&hash, msg.ntcp2_size())))
            .filter_map(|b| b)
            .min_by_key(|b| b.bid)
        {
            Some(bid) => Ok(Box::new(bid.send((hash, msg)).map(|_| ()).map_err(|_| {
                io::Error::new(io::ErrorKind::Other, "Error in transport::Engine")
            }))),
            None => Err((hash, msg)),
        }
    }
}

impl CommSystem for Manager {
    fn addresses(&self) -> Vec<RouterAddress> {
        vec![self.ntcp.address(), self.ntcp2.address()]
    }

    fn start(&mut self, rsk: RouterSecretKeys) -> IoFuture<()> {
        let engine = self.engine.take().expect("Cannot call listen() twice");

        let listener = self
            .ntcp
            .listen(rsk.rid.clone(), rsk.signing_private_key.clone())
            .map_err(|e| {
                error!("NTCP listener error: {}", e);
                e
            });

        let listener2 = self.ntcp2.listen(&rsk.rid).map_err(|e| {
            error!("NTCP2 listener error: {}", e);
            e
        });

        Box::new(
            engine
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "Error in transport::Engine"))
                .join3(listener, listener2)
                .map(|_| ()),
        )
    }
}

impl Future for Engine {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<(), ()> {
        while let Async::Ready(f) = self.engines.poll()? {
            if let Some((from, msg)) = f {
                self.msg_handler.handle(from, msg);
            }
        }
        Ok(Async::NotReady)
    }
}

#[cfg(test)]
mod tests {
    use futures::{lazy, Async, Stream};
    use std::io::{self, Read, Write};
    use std::sync::{Arc, Mutex};
    use tempfile::tempdir;
    use tokio_io::{AsyncRead, AsyncWrite};

    use super::*;

    pub struct NetworkCable {
        alice_to_bob: Vec<u8>,
        bob_to_alice: Vec<u8>,
    }

    impl NetworkCable {
        pub fn new() -> Arc<Mutex<Self>> {
            Arc::new(Mutex::new(NetworkCable {
                alice_to_bob: Vec::new(),
                bob_to_alice: Vec::new(),
            }))
        }
    }

    pub struct AliceNet {
        cable: Arc<Mutex<NetworkCable>>,
    }

    impl AliceNet {
        pub fn new(cable: Arc<Mutex<NetworkCable>>) -> Self {
            AliceNet { cable }
        }
    }

    impl Read for AliceNet {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let mut cable = self.cable.lock().unwrap();
            let n_in = cable.bob_to_alice.len();
            let n_out = buf.len();
            if n_in == 0 {
                Err(io::Error::new(io::ErrorKind::WouldBlock, ""))
            } else if n_out < n_in {
                buf.copy_from_slice(&cable.bob_to_alice[..n_out]);
                cable.bob_to_alice = cable.bob_to_alice.split_off(n_out);
                Ok(n_out)
            } else {
                (&mut buf[..n_in]).copy_from_slice(&cable.bob_to_alice);
                cable.bob_to_alice.clear();
                Ok(n_in)
            }
        }
    }

    impl Write for AliceNet {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let mut cable = self.cable.lock().unwrap();
            cable.alice_to_bob.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl AsyncRead for AliceNet {}
    impl AsyncWrite for AliceNet {
        fn shutdown(&mut self) -> io::Result<Async<()>> {
            Ok(().into())
        }
    }

    pub struct BobNet {
        cable: Arc<Mutex<NetworkCable>>,
    }

    impl BobNet {
        pub fn new(cable: Arc<Mutex<NetworkCable>>) -> Self {
            BobNet { cable }
        }
    }

    impl Read for BobNet {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let mut cable = self.cable.lock().unwrap();
            let n_in = cable.alice_to_bob.len();
            let n_out = buf.len();
            if n_in == 0 {
                Err(io::Error::new(io::ErrorKind::WouldBlock, ""))
            } else if n_out < n_in {
                buf.copy_from_slice(&cable.alice_to_bob[..n_out]);
                cable.alice_to_bob = cable.alice_to_bob.split_off(n_out);
                Ok(n_out)
            } else {
                (&mut buf[..n_in]).copy_from_slice(&cable.alice_to_bob);
                cable.alice_to_bob.clear();
                Ok(n_in)
            }
        }
    }

    impl Write for BobNet {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let mut cable = self.cable.lock().unwrap();
            cable.bob_to_alice.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl AsyncRead for BobNet {}
    impl AsyncWrite for BobNet {
        fn shutdown(&mut self) -> io::Result<Async<()>> {
            Ok(().into())
        }
    }

    #[test]
    fn handle_send() {
        let (message, mut message_rx) = mpsc::unbounded();
        let (timestamp, mut timestamp_rx) = mpsc::unbounded();
        let handle = Handle { message, timestamp };

        let hash = Hash::from_bytes(&[0; 32]);
        let msg = Message::dummy_data();
        let mut msg2 = Message::dummy_data();
        // Ensure the two messages are identical
        msg2.expiration = msg.expiration.clone();

        // Run on a task context
        lazy(move || {
            // Check the queue is empty
            assert_eq!(
                (message_rx.poll(), timestamp_rx.poll()),
                (Ok(Async::NotReady), Ok(Async::NotReady))
            );

            // Send a message
            handle.send(hash.clone(), msg).unwrap();

            // Check it was received
            assert_eq!(
                (message_rx.poll(), timestamp_rx.poll()),
                (Ok(Async::Ready(Some((hash, msg2)))), Ok(Async::NotReady))
            );

            // Check the queue is empty again
            assert_eq!(
                (message_rx.poll(), timestamp_rx.poll()),
                (Ok(Async::NotReady), Ok(Async::NotReady))
            );

            Ok::<(), ()>(())
        }).wait()
        .unwrap();
    }

    #[test]
    fn handle_timestamp() {
        let (message, mut message_rx) = mpsc::unbounded();
        let (timestamp, mut timestamp_rx) = mpsc::unbounded();
        let handle = Handle { message, timestamp };

        // Run on a task context
        lazy(move || {
            // Check the queue is empty
            assert_eq!(
                (message_rx.poll(), timestamp_rx.poll()),
                (Ok(Async::NotReady), Ok(Async::NotReady))
            );

            // Send a message
            let hash = Hash::from_bytes(&[0; 32]);
            handle.timestamp(hash.clone(), 42).unwrap();

            // Check it was received
            assert_eq!(
                (message_rx.poll(), timestamp_rx.poll()),
                (Ok(Async::NotReady), Ok(Async::Ready(Some((hash, 42)))))
            );

            // Check the queue is empty again
            assert_eq!(
                (message_rx.poll(), timestamp_rx.poll()),
                (Ok(Async::NotReady), Ok(Async::NotReady))
            );

            Ok::<(), ()>(())
        }).wait()
        .unwrap();
    }

    #[test]
    fn manager_addresses() {
        let dir = tempdir().unwrap();

        let ntcp_addr = "127.0.0.1:0".parse().unwrap();
        let ntcp2_addr = "127.0.0.2:0".parse().unwrap();
        let ntcp2_keyfile = dir.path().join("test.ntcp2.keys.dat");

        struct MockMessageHandler;

        impl InboundMessageHandler for MockMessageHandler {
            fn handle(&self, from: Hash, msg: Message) {}
        }

        let manager = Manager::new(
            Arc::new(MockMessageHandler {}),
            ntcp_addr,
            ntcp2_addr,
            ntcp2_keyfile.to_str().unwrap(),
        );
        let addrs = manager.addresses();

        assert_eq!(addrs[0].addr(), Some(ntcp_addr));
        assert_eq!(addrs[1].addr(), Some(ntcp2_addr));
    }
}
