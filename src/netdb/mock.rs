use futures::{sync::mpsc, try_ready, Future, Poll, Stream};
use std::collections::HashMap;
use std::sync::Arc;

use super::client::Query;
use crate::{
    data::{Hash, RouterInfo},
    netdb::errors::LookupError,
    router::Context,
};

pub struct MockNetDb {
    client_rx: mpsc::UnboundedReceiver<Query>,
    ri_ds: HashMap<Hash, RouterInfo>,
}

impl MockNetDb {
    pub fn new(ctx: Arc<Context>, client_rx: mpsc::UnboundedReceiver<Query>) -> Self {
        MockNetDb {
            client_rx,
            ri_ds: HashMap::new(),
        }
    }

    pub fn store_router_info(&mut self, key: Hash, ri: RouterInfo) {
        self.ri_ds.insert(key, ri);
    }
}

impl Future for MockNetDb {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            if let Some(Query::LookupRouterInfo(query)) = try_ready!(self.client_rx.poll()) {
                query
                    .response_tx
                    .send(
                        self.ri_ds
                            .get(&query.key)
                            .cloned()
                            .ok_or(LookupError::NotFound),
                    )
                    .unwrap()
            }
        }
    }
}
