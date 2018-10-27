use futures::{
    future::{self, Either},
    sync::oneshot,
    Future,
};
use std::sync::Arc;
use std::time::Duration;
use tokio_timer::Timeout;

use super::PendingLookup;
use data::{Hash, RouterInfo};
use i2np::{DatabaseLookup, DatabaseLookupType};
use router::{types::LookupError, Context};

type LookupFuture<T> = Box<Future<Item = T, Error = LookupError> + Send>;

pub fn lookup_db_entry<T: Send + 'static>(
    ctx: Arc<Context>,
    key: Hash,
    lookup_type: DatabaseLookupType,
    ff: RouterInfo,
    pending: &mut PendingLookup<T>,
    timeout_ms: u64,
) -> LookupFuture<T> {
    debug!(
        "Looking up key {} with floodfill {}",
        key,
        ff.router_id.hash()
    );
    let from = ctx.ri.read().unwrap().router_id.hash();

    // Set up a channel so we get notified when the RouterInfo arrives
    let (tx_store, rx_store) = oneshot::channel();
    pending.entry(key.clone()).or_default().push(tx_store);

    let lookup = rx_store
        .select2(send_lookup(
            ctx,
            key,
            from,
            lookup_type,
            vec![],
            vec![ff],
            timeout_ms,
        )).then(|res| match res {
            Ok(Either::A((ri, _))) => Box::new(future::ok(ri)),
            Ok(Either::B(((), _))) => unreachable!(),
            Err(Either::A((_, _))) => Box::new(future::err(LookupError::NotFound)),
            Err(Either::B((e, _))) => Box::new(future::err(e)),
        });

    // Add a timeout
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

fn send_lookup(
    ctx: Arc<Context>,
    key: Hash,
    from: Hash,
    lookup_type: DatabaseLookupType,
    excluded_peers: Vec<Hash>,
    ffs: Vec<RouterInfo>,
    timeout_ms: u64,
) -> LookupFuture<()> {
    let ff_hashes: Vec<Hash> = ffs.iter().map(|ff| ff.router_id.hash()).collect();

    Box::new(
        future::select_ok(ffs.into_iter().map(|ff| {
            let mut excluded_peers = excluded_peers.clone();

            // Add the parallel peers to the exclusion list
            let ff_hash = ff.router_id.hash();
            for hash in &ff_hashes {
                if *hash != ff_hash {
                    excluded_peers.push(hash.clone());
                }
            }

            // Create the lookup
            let dlm = DatabaseLookup::create_msg(
                key.clone(),
                from.clone(),
                lookup_type,
                excluded_peers.clone(),
            );

            // Add this peer to the exclusion list
            excluded_peers.push(ff_hash);

            // Send the lookup
            let lookup: LookupFuture<()> = match ctx.comms.read().unwrap().send(ff.clone(), dlm) {
                Ok(f) => {
                    // Set up a channel so we get notified if a DatabaseSearchReply arrives
                    let (tx_dsr, rx_dsr) = oneshot::channel();
                    ctx.msg_handler.register_lookup(key.clone(), tx_dsr);

                    let ctx = ctx.clone();
                    let key = key.clone();
                    let from = from.clone();

                    Box::new(
                        f.map_err(|_| LookupError::SendFailure)
                            .and_then(|_| {
                                // Wait on the DatabaseSearchReply. If the lookup succeeds
                                // (returning a DatabaseStore), this future will hang, but the
                                // rx_store future in lookup_db_entry() will fire, causing this
                                // future to be dropped.
                                rx_dsr.map_err(|_| LookupError::TimedOut)
                            }).and_then(move |dsr| {
                                debug!("Received {}", dsr);

                                // Look up each of the returned peers
                                let peer_lookups = dsr
                                    .peers
                                    .into_iter()
                                    .map(|peer| {
                                        ctx.netdb.write().unwrap().lookup_router_info(
                                            Some(ctx.clone()),
                                            &peer,
                                            timeout_ms,
                                            Some(ff.clone()),
                                        )
                                    }).collect();

                                // Collect all lookups that succeed
                                let peer_ris = future::loop_fn(
                                    (vec![], peer_lookups),
                                    |(mut found, peer_lookups)| {
                                        future::select_ok(peer_lookups).and_then(
                                            |(ri, remaining)| {
                                                found.push(ri);
                                                if remaining.is_empty() {
                                                    Ok(future::Loop::Break(found))
                                                } else {
                                                    Ok(future::Loop::Continue((found, remaining)))
                                                }
                                            },
                                        )
                                    },
                                );

                                // Fire off our desired lookup to the new peers
                                peer_ris.and_then(move |ffs| {
                                    send_lookup(
                                        ctx,
                                        key,
                                        from,
                                        lookup_type,
                                        excluded_peers,
                                        ffs,
                                        timeout_ms,
                                    )
                                })
                            }),
                    )
                }
                Err((_, _)) => Box::new(future::err(LookupError::NotFound)),
            };

            lookup
        })).map(|((), _)| ()),
    )
}
