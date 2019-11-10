//! Transports used for point-to-point communication between I2P routers.

use futures::{future::lazy, Future, Poll, Sink, StartSend};
use std::iter::once;
use std::sync::Arc;
use tokio::{executor::spawn, io};

use crate::crypto::dh::DHSessionKeyBuilder;
use crate::data::{Hash, RouterAddress, RouterInfo};
use crate::i2np::Message;
use crate::router::{
    config,
    types::{CommSystem, Distributor},
    Context,
};

pub mod ntcp;
pub mod ntcp2;
mod session;

type IoFuture<T> = Box<dyn Future<Item = T, Error = io::Error> + Send>;

/// A bid from a transport indicating how much it thinks it will "cost" to
/// send a particular message.
struct Bid {
    bid: u32,
    sink: Box<dyn Sink<SinkItem = (RouterInfo, Message), SinkError = io::Error> + Send>,
}

impl Sink for Bid {
    type SinkItem = (RouterInfo, Message);
    type SinkError = io::Error;

    fn start_send(
        &mut self,
        message: Self::SinkItem,
    ) -> StartSend<Self::SinkItem, Self::SinkError> {
        self.sink.start_send(message)
    }

    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        self.sink.poll_complete()
    }
}

/// Coordinates the sending and receiving of frames over the various supported
/// transports.
pub struct Manager<D: Distributor> {
    ntcp: ntcp::Manager<D>,
    ntcp2: ntcp2::Manager<D>,
}

trait Transport {
    fn is_established(&self, hash: &Hash) -> bool;

    fn bid(&self, peer: &RouterInfo, msg_size: usize) -> Option<Bid>;
}

impl<D: Distributor> Manager<D> {
    pub fn from_config(config: &config::Config, distributor: D) -> Self {
        let ntcp_addr = config
            .get_str(config::NTCP_LISTEN)
            .expect("Must configure an NTCP address")
            .parse()
            .unwrap();
        let ntcp2_addr = config
            .get_str(config::NTCP2_LISTEN)
            .expect("Must configure an NTCP2 address")
            .parse()
            .unwrap();
        let ntcp2_keyfile = config.get_str(config::NTCP2_KEYFILE).unwrap();

        let ntcp_manager = ntcp::Manager::new(ntcp_addr, distributor.clone());
        let ntcp2_manager =
            match ntcp2::Manager::from_file(ntcp2_addr, &ntcp2_keyfile, distributor.clone()) {
                Ok(ret) => ret,
                Err(_) => {
                    let ntcp2_manager = ntcp2::Manager::new(ntcp2_addr, distributor);
                    ntcp2_manager.to_file(&ntcp2_keyfile).unwrap();
                    ntcp2_manager
                }
            };
        Manager {
            ntcp: ntcp_manager,
            ntcp2: ntcp2_manager,
        }
    }
}

impl<D: Distributor> CommSystem for Manager<D> {
    fn addresses(&self) -> Vec<RouterAddress> {
        vec![self.ntcp.address(), self.ntcp2.address()]
    }

    fn start(&mut self, ctx: Arc<Context>) -> Box<dyn Future<Item = (), Error = ()> + Send> {
        self.ntcp.set_context(ctx.clone());
        self.ntcp2.set_context(ctx.clone());

        let listener = self
            .ntcp
            .listen(ctx.keys.rid.clone(), ctx.keys.signing_private_key.clone())
            .map_err(|e| {
                error!("NTCP listener error: {}", e);
            });

        let listener2 = self.ntcp2.listen(&ctx.keys.rid).map_err(|e| {
            error!("NTCP2 listener error: {}", e);
        });

        Box::new(lazy(|| {
            spawn(listener);
            spawn(listener2);
            Ok(())
        }))
    }

    fn is_established(&self, hash: &Hash) -> bool {
        self.ntcp.is_established(hash) || self.ntcp2.is_established(hash)
    }

    /// Send an I2NP message to a peer over one of our transports.
    ///
    /// Returns an Err giving back the message if it cannot be sent over any of
    /// our transports.
    fn send(&self, peer: RouterInfo, msg: Message) -> Result<IoFuture<()>, (RouterInfo, Message)> {
        match once(self.ntcp.bid(&peer, msg.size()))
            .chain(once(self.ntcp2.bid(&peer, msg.ntcp2_size())))
            .filter_map(|b| b)
            .min_by_key(|b| b.bid)
        {
            Some(bid) => Ok(Box::new(bid.send((peer, msg)).map(|_| ()).map_err(|_| {
                io::Error::new(io::ErrorKind::Other, "Error in transport::Engine")
            }))),
            None => Err((peer, msg)),
        }
    }
}

#[cfg(test)]
mod tests {
    use futures::Async;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use tempfile::tempdir;
    use tokio::io::{self, AsyncRead, AsyncWrite, Read, Write};

    use super::*;
    use crate::router::mock::MockDistributor;

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
    fn manager_addresses() {
        let dir = tempdir().unwrap();

        let ntcp_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let ntcp2_addr: SocketAddr = "127.0.0.2:0".parse().unwrap();
        let ntcp2_keyfile = dir.path().join("test.ntcp2.keys.dat");

        let mut config = config::Config::default();
        config
            .set(config::NTCP_LISTEN, ntcp_addr.to_string())
            .unwrap();
        config
            .set(config::NTCP2_LISTEN, ntcp2_addr.to_string())
            .unwrap();
        config
            .set(config::NTCP2_KEYFILE, ntcp2_keyfile.to_str())
            .unwrap();

        let distributor = MockDistributor::new();
        let manager = Manager::from_config(&config, distributor);
        let addrs = manager.addresses();

        assert_eq!(addrs[0].addr(), Some(ntcp_addr));
        assert_eq!(addrs[1].addr(), Some(ntcp2_addr));
    }
}
