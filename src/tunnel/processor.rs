//! Fast-path processing of tunnel data in participating tunnels.

use futures::{sync::mpsc, try_ready, Async, Future, Poll, Stream};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime};
use tokio::{io, spawn, timer::Delay};
use tokio_threadpool::blocking;

use super::{encryption::LayerCipher, HopConfig, HopData, TUNNEL_LIFETIME};
use crate::data::{Hash, RouterInfo, TunnelId};
use crate::i2np::{Message, MessagePayload, TunnelData};
use crate::router::types::CommSystem;
use crate::util::DecayingBloomFilter;

type IoFuture<T> = Box<dyn Future<Item = T, Error = io::Error> + Send>;

/// Interval on which we expire tunnels we are participating in.
const EXPIRE_TUNNELS_INTERVAL: u64 = 10;

macro_rules! try_poll {
    ($f:expr, $parent:expr, $state:expr) => {
        match $f {
            Ok(Async::Ready(t)) => t,
            Ok(Async::NotReady) => {
                $parent.state = Some($state);
                return Ok(Async::NotReady);
            }
            Err(e) => {
                // We can't recover from any error
                error!("Error while processing a hop: {:?}", e);
                return Err(());
            }
        }
    };
}

enum HopProcessorState {
    Processing((RouterInfo, TunnelId), TunnelData, LayerCipher),
    Sending(IoFuture<()>),
}

/// A [`Future`] that processes a single [`TunnelData`] messages.
///
/// Encryption operations are handled using the [`blocking()`] threadpool.
struct HopProcessor {
    state: Option<HopProcessorState>,
    comms: Arc<RwLock<dyn CommSystem>>,
}

impl HopProcessor {
    fn new(
        next_hop: (RouterInfo, TunnelId),
        td: TunnelData,
        layer_cipher: LayerCipher,
        comms: Arc<RwLock<dyn CommSystem>>,
    ) -> Self {
        HopProcessor {
            state: Some(HopProcessorState::Processing(next_hop, td, layer_cipher)),
            comms,
        }
    }
}

impl Future for HopProcessor {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<(), ()> {
        loop {
            let next_state = match self.state.take().unwrap() {
                HopProcessorState::Processing(next_hop, mut td, layer_cipher) => {
                    // Process the layer
                    try_poll!(
                        blocking(|| {
                            layer_cipher.encrypt_layer(&mut td);
                        }),
                        self,
                        HopProcessorState::Processing(next_hop, td, layer_cipher)
                    );

                    // Update the tunnel ID for the next hop
                    td.tid = next_hop.1;

                    match self.comms.read().unwrap().send(
                        next_hop.0,
                        Message::from_payload(MessagePayload::TunnelData(td)),
                    ) {
                        Ok(f) => HopProcessorState::Sending(f),
                        Err((ri, msg)) => {
                            error!(
                                "Could not send message to {} over any of our transports: {}",
                                ri.router_id.hash(),
                                msg
                            );
                            return Err(());
                        }
                    }
                }
                HopProcessorState::Sending(mut f) => {
                    try_poll!(f.poll(), self, HopProcessorState::Sending(f));
                    return Ok(Async::Ready(()));
                }
            };
            self.state = Some(next_state);
        }
    }
}

/// A [`Future`] that handles incoming [`TunnelData`] messages for a single participating
/// tunnel.
///
/// Each message is spawned into its own task, which uses the [`blocking()`] threadpool
/// for encryption operations.
///
/// Currently only supports intermediate hops, not IBGWs or OBEPs.
pub struct Participant {
    new_participating_rx: mpsc::Receiver<(TunnelId, HopConfig)>,
    participating: HashMap<TunnelId, HopConfig>,
    filter: DecayingBloomFilter,
    expire_tunnels_timer: Delay,
    decay_filter_timer: Delay,
    ib_rx: mpsc::Receiver<(Hash, Message)>,
    comms: Arc<RwLock<dyn CommSystem>>,
}

impl Participant {
    pub fn new(
        new_participating_rx: mpsc::Receiver<(TunnelId, HopConfig)>,
        ib_rx: mpsc::Receiver<(Hash, Message)>,
        comms: Arc<RwLock<dyn CommSystem>>,
    ) -> Self {
        Participant {
            new_participating_rx,
            participating: HashMap::new(),
            filter: DecayingBloomFilter::new(20_000), // TODO: Configure this based on bandwidth
            expire_tunnels_timer: Delay::new(
                Instant::now() + Duration::from_secs(EXPIRE_TUNNELS_INTERVAL),
            ),
            decay_filter_timer: Delay::new(Instant::now() + Duration::from_secs(TUNNEL_LIFETIME)),
            ib_rx,
            comms,
        }
    }
}

impl Future for Participant {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<(), ()> {
        loop {
            // Add new tunnels
            while let Async::Ready(Some((tid, config))) = self
                .new_participating_rx
                .poll()
                .map_err(|e| error!("Error while polling for new participating tunnels: {:?}", e))?
            {
                self.participating.insert(tid, config);
            }

            // Handle periodic work
            if let Ok(Async::Ready(())) = self.expire_tunnels_timer.poll() {
                // Drop expired tunnels
                let now = SystemTime::now();
                self.participating
                    .retain(|_tid, config| config.expires > now);

                // Reset timer
                self.expire_tunnels_timer =
                    Delay::new(Instant::now() + Duration::from_secs(EXPIRE_TUNNELS_INTERVAL));
            }
            if let Ok(Async::Ready(())) = self.decay_filter_timer.poll() {
                // Decay the filter
                self.filter.decay();

                // Reset timer
                self.decay_filter_timer =
                    Delay::new(Instant::now() + Duration::from_secs(TUNNEL_LIFETIME));
            }

            // Process the next message
            if let Some((from, msg)) = try_ready!(self.ib_rx.poll()) {
                match msg.payload {
                    MessagePayload::TunnelData(td) => {
                        // Find the tunnel ID
                        if let Some(config) = self.participating.get(&td.tid) {
                            // Checks that the message came from the same previous hop as before.
                            // Does not apply to IBGWs.
                            match &config.hop_data {
                                HopData::InboundGateway(_) => (),
                                HopData::Intermediate(from_ident, _)
                                | HopData::OutboundEndpoint(from_ident) => {
                                    if from != *from_ident {
                                        warn!("Dropping TunnelData message: from the wrong peer");
                                        continue;
                                    }
                                }
                            }

                            // Check for duplicates by feeding the XOR of the IV and first block
                            // into a decaying Bloom filter.
                            let filter_value: Vec<_> =
                                (0..16).map(|i| td.data[i] ^ td.data[i + 16]).collect();
                            if self.filter.feed(&filter_value) {
                                warn!("Dropping TunnelData message: duplicate");
                                continue;
                            }

                            // Okay, we want to process this message
                            match &config.hop_data {
                                HopData::InboundGateway(_) => unimplemented!(),
                                HopData::Intermediate(_, next_hop) => {
                                    spawn(HopProcessor::new(
                                        next_hop.clone(),
                                        td,
                                        config.layer_cipher.clone(),
                                        self.comms.clone(),
                                    ));
                                }
                                HopData::OutboundEndpoint(_) => unimplemented!(),
                            }
                        } else {
                            warn!("Dropping TunnelData message: unknown TunnelId");
                        }
                    }
                    _ => {
                        warn!("Received unexpected message from {}:\n{}", from, msg);
                    }
                }
            } else {
                // Distributor has gone, we are done
                return Ok(Async::Ready(()));
            }
        }
    }
}
