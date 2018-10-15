use futures::{future, sync::oneshot, Future};
use std::sync::Arc;
use std::time::Duration;
use tokio_timer::Timeout;

use super::PendingLookup;
use data::{Hash, RouterInfo};
use i2np::{DatabaseLookup, DatabaseLookupType};
use router::{types::LookupError, Context};

type LookupFuture<T> = Box<Future<Item = T, Error = LookupError> + Send>;

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
) -> LookupFuture<T> {
    debug!(
        "Looking up key {} with floodfill {}",
        key,
        ff.router_id.hash()
    );
    let from = ctx.ri.read().unwrap().router_id.hash();

    // Set up a channel so we get notified when the RouterInfo arrives
    let (tx, rx) = oneshot::channel();
    pending.entry(key.clone()).or_default().push(tx);

    // Create the lookup
    let dlm = DatabaseLookup::create_msg(key, from, lookup_type);

    // Send the lookup...
    match ctx.comms.read().unwrap().send(ff, dlm) {
        Ok(f) => {
            // ... and wait on the response
            let lookup = f
                .map_err(|_| LookupError::SendFailure)
                .and_then(|_| rx.map_err(|_| LookupError::TimedOut));

            // Add a timeout
            let timed = Timeout::new(lookup, Duration::from_millis(timeout_ms)).map_err(|e| {
                if e.is_inner() {
                    e.into_inner().unwrap()
                } else if e.is_elapsed() {
                    LookupError::TimedOut
                } else {
                    LookupError::TimerFailure
                }
            });

            Box::new(timed)
        }
        Err((_, _)) => Box::new(future::err(LookupError::NotFound)),
    }
}
