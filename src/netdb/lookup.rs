use futures::{
    future::{self, Either},
    sync::oneshot,
    Future,
};
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tokio_timer::Timeout;

use super::{create_routing_key, PendingLookup, XorMetric};
use crate::data::{Hash, RouterInfo};
use crate::i2np::{DatabaseLookup, DatabaseLookupType, DatabaseSearchReply, Message};
use crate::router::{types::LookupError, Context};

/// The time before we give up on a peer and try the next one.
///
/// Much shorter than the message's expire time. Longer than the typical response time of
/// 1.0 - 1.5 sec, but short enough that we move on to another peer quickly.
const SINGLE_LOOKUP_TIMEOUT: u64 = 5;

type LookupFuture<T, E> = Box<dyn Future<Item = T, Error = E> + Send>;

fn wait_for_search_reply(
    ctx: &Arc<Context>,
    peer: RouterInfo,
    key: Hash,
    dlm: Message,
) -> LookupFuture<Option<DatabaseSearchReply>, LookupError> {
    let peer_hash = peer.router_id.hash();
    match ctx.comms.read().unwrap().send(peer, dlm) {
        Ok(f) => {
            // Set up a channel so we get notified if a DatabaseSearchReply arrives
            let (tx_dsr, rx_dsr) = oneshot::channel();
            ctx.msg_handler.register_lookup(peer_hash, key, tx_dsr);

            let received_dsr = f.map_err(|_| LookupError::SendFailure).and_then(|_| {
                // Wait on the DatabaseSearchReply. If the lookup succeeds
                // (returning a DatabaseStore), this future will hang, but the
                // rx_store future in lookup_db_entry() will fire, causing this
                // future to be dropped.
                rx_dsr.map(Some).map_err(|_| LookupError::TimedOut)
            });

            Box::new(
                Timeout::new(received_dsr, Duration::from_secs(SINGLE_LOOKUP_TIMEOUT)).or_else(
                    move |e| {
                        if e.is_inner() {
                            Err(e.into_inner().unwrap())
                        } else if e.is_elapsed() {
                            // On timeout, continue to next peer
                            debug!("Timed out waiting for DatabaseSearchReply message");
                            Ok(None)
                        } else {
                            Err(LookupError::TimerFailure)
                        }
                    },
                ),
            )
        }
        Err((_, _)) => Box::new(future::err(LookupError::SendFailure)),
    }
}

fn process_dsr(
    ctx: Arc<Context>,
    tried: &HashSet<Hash>,
    dsr: DatabaseSearchReply,
) -> LookupFuture<Vec<RouterInfo>, LookupError> {
    if dsr.peers.is_empty() {
        Box::new(future::ok(vec![]))
    } else if !tried.contains(&dsr.from) {
        // DSR.from is unauthenticated, so ignore if not in the set of peers we know we queried
        warn!("Received unsolicited DSR from {}, ignoring", dsr.from);
        Box::new(future::ok(vec![]))
    } else {
        // Get RouterInfo for peer we queried
        let from_ri = ctx.netdb.write().unwrap().lookup_router_info(
            Some(ctx.clone()),
            &dsr.from,
            SINGLE_LOOKUP_TIMEOUT * 1000,
            None,
        );

        let processed = from_ri.and_then(move |from| {
            // Look up each of the returned peers with the router that sent us the DSR
            let peer_lookups = dsr
                .peers
                .into_iter()
                .map(|peer| {
                    ctx.netdb.write().unwrap().lookup_router_info(
                        Some(ctx.clone()),
                        &peer,
                        SINGLE_LOOKUP_TIMEOUT * 1000,
                        Some(from.clone()),
                    )
                })
                .collect();

            // Collect all lookups that succeed
            future::loop_fn((vec![], peer_lookups), |(mut found, peer_lookups)| {
                future::select_ok(peer_lookups).and_then(|(ri, remaining)| {
                    found.push(ri);
                    if remaining.is_empty() {
                        Ok(future::Loop::Break(found))
                    } else {
                        Ok(future::Loop::Continue((found, remaining)))
                    }
                })
            })
        });

        Box::new(processed)
    }
}

struct IterativeLookup {
    ctx: Arc<Context>,
    key: Hash,
    rk: Hash,
    from: Hash,
    lookup_type: DatabaseLookupType,
    to_try: BTreeMap<XorMetric, RouterInfo>,
    tried: HashSet<Hash>,
}

impl IterativeLookup {
    /// Returns the lookup state and the first peer to try
    fn new(
        ctx: Arc<Context>,
        key: Hash,
        from: Hash,
        lookup_type: DatabaseLookupType,
        ffs: Vec<RouterInfo>,
    ) -> (Self, RouterInfo) {
        let rk = create_routing_key(&key);

        let mut to_try = BTreeMap::new();
        for ri in ffs {
            to_try.insert(XorMetric::for_hash(&ri.router_id.hash(), &rk), ri);
        }

        let first = to_try.keys().next().cloned().unwrap();
        let first = to_try.remove(&first).unwrap();

        (
            IterativeLookup {
                ctx,
                key,
                rk,
                from,
                lookup_type,
                to_try,
                tried: HashSet::new(),
            },
            first,
        )
    }

    fn process_peer(mut self, peer: RouterInfo) -> LookupFuture<Self, ()> {
        // Create the lookup
        let dlm = DatabaseLookup::create_msg(self.key.clone(), self.from.clone(), self.lookup_type);

        // Send the lookup
        let peer_hash = peer.router_id.hash();
        debug!("Sending lookup to peer {}:\n{}", peer_hash, dlm);
        self.tried.insert(peer_hash);
        let reply = wait_for_search_reply(&self.ctx, peer, self.key.clone(), dlm).or_else(|e| {
            error!("Error while sending lookup: {}", e);
            Ok(None)
        });

        // Process the reply
        let processed = reply.and_then(move |dsr| {
            let processed: LookupFuture<_, _> = if let Some(dsr) = dsr {
                let peer_ris = process_dsr(self.ctx.clone(), &self.tried, dsr);

                let processed = peer_ris.then(move |ret| {
                    match ret {
                        Ok(ris) => {
                            // Update the internal state
                            for ri in ris {
                                let hash = ri.router_id.hash();
                                if !self.tried.contains(&hash) {
                                    self.to_try.insert(XorMetric::for_hash(&hash, &self.rk), ri);
                                }
                            }
                        }
                        Err(e) => error!("Error while processing DSR: {}", e),
                    }
                    Ok(self)
                });

                Box::new(processed)
            } else {
                Box::new(future::ok(self))
            };
            processed
        });

        Box::new(processed.map_err(|()| unreachable!()))
    }

    fn select_next_peer(&mut self) -> Option<RouterInfo> {
        // Return the next peer to try, if any
        debug!("{} more peers to try", self.to_try.len());
        let next = self.to_try.keys().next().cloned();
        next.map(|next| self.to_try.remove(&next).unwrap())
    }
}

fn iterative_lookup(
    ctx: Arc<Context>,
    key: Hash,
    from: Hash,
    lookup_type: DatabaseLookupType,
    ff: RouterInfo,
) -> LookupFuture<(), ()> {
    Box::new(future::loop_fn(
        IterativeLookup::new(ctx, key, from, lookup_type, vec![ff]),
        move |(lookup, peer)| {
            lookup.process_peer(peer).and_then(|mut lookup| {
                if let Some(peer) = lookup.select_next_peer() {
                    Ok(future::Loop::Continue((lookup, peer)))
                } else {
                    // All peers have either timed out or returned DSRs, and we
                    // have no more peers to try, so we are finished.
                    Ok(future::Loop::Break(()))
                }
            })
        },
    ))
}

/// Looks up a netDb entry with the given floodfill router.
///
/// If the floodfill does not have the entry, the lookup will time out, as
/// DatabaseSearchReply messages are not yet handled.
pub fn lookup_db_entry<T: Send + 'static>(
    ctx: Arc<Context>,
    key: Hash,
    lookup_type: DatabaseLookupType,
    ff: RouterInfo,
    pending: &mut PendingLookup<T>,
    timeout_ms: u64,
) -> LookupFuture<T, LookupError> {
    let from = ctx.ri.read().unwrap().router_id.hash();

    // Set up a channel so we get notified when the RouterInfo arrives
    let (tx_store, rx_store) = oneshot::channel();
    pending.entry(key.clone()).or_default().push(tx_store);

    let lookup = rx_store
        .select2(iterative_lookup(ctx, key, from, lookup_type, ff))
        .then(|res| match res {
            Ok(Either::A((ri, _))) => Box::new(future::ok(ri)),
            Ok(Either::B(((), _))) => Box::new(future::err(LookupError::NotFound)),
            Err(Either::A((_, _))) => Box::new(future::err(LookupError::NotFound)),
            Err(Either::B(((), _))) => unreachable!(),
        });

    Box::new(
        Timeout::new(lookup, Duration::from_millis(timeout_ms)).map_err(|e| {
            if e.is_inner() {
                e.into_inner().unwrap()
            } else if e.is_elapsed() {
                LookupError::TimedOut
            } else {
                LookupError::TimerFailure
            }
        }),
    )
}

/// Explores the netDb for a given key.
pub fn explore_netdb(
    ctx: Arc<Context>,
    key: Hash,
    ff: RouterInfo,
    timeout_ms: u64,
) -> LookupFuture<(), LookupError> {
    let from = ctx.ri.read().unwrap().router_id.hash();

    let explorer =
        iterative_lookup(ctx, key, from, DatabaseLookupType::Exploratory, ff).then(|_| {
            // No more peers to explore, so we are done
            debug!("Finished exploratory lookup");
            Ok(())
        });

    Box::new(
        Timeout::new(explorer, Duration::from_millis(timeout_ms)).map_err(|e| {
            if e.is_inner() {
                e.into_inner().unwrap()
            } else if e.is_elapsed() {
                LookupError::TimedOut
            } else {
                LookupError::TimerFailure
            }
        }),
    )
}
