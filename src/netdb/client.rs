//! An asynchronous NetDB client.

use futures::{
    sync::{mpsc, oneshot},
    Async, Future, Poll,
};
use std::fmt;
use std::sync::{Arc, RwLock};
use tokio_executor::spawn;

use crate::{
    data::{Hash, LeaseSet, RouterInfo},
    router::{
        types::{LookupError, NetworkDatabase},
        Context,
    },
};

pub enum Error {
    Lookup(LookupError),
    Closed,
}

impl From<LookupError> for Error {
    fn from(e: LookupError) -> Self {
        Error::Lookup(e)
    }
}

#[cfg_attr(tarpaulin, skip)]
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Lookup(e) => write!(f, "Lookup error: {}", e),
            Error::Closed => write!(f, "NetDB closed"),
        }
    }
}

pub enum Query {
    KnownRouters(oneshot::Sender<usize>),
    SelectClosestFloodfill(Hash, oneshot::Sender<Option<RouterInfo>>),
    LookupRouterInfo(
        Hash,
        u64,
        Option<RouterInfo>,
        oneshot::Sender<Result<RouterInfo, LookupError>>,
    ),
    LookupLeaseSet(
        Hash,
        u64,
        Option<Hash>,
        oneshot::Sender<Result<LeaseSet, LookupError>>,
    ),
}

impl Query {
    pub(super) fn handle(self, netdb: &Arc<RwLock<dyn NetworkDatabase>>, ctx: &Arc<Context>) {
        match self {
            Query::KnownRouters(ret) => {
                if ret.send(netdb.read().unwrap().known_routers()).is_err() {
                    warn!("Completed known routers query, but client gave up");
                }
            }
            Query::SelectClosestFloodfill(key, ret) => {
                if ret
                    .send(netdb.read().unwrap().select_closest_ff(&key))
                    .is_err()
                {
                    warn!("Completed floodfill selection, but client gave up");
                }
            }
            Query::LookupRouterInfo(key, timeout_ms, from_peer, ret) => {
                spawn(
                    netdb
                        .write()
                        .unwrap()
                        .lookup_router_info(Some(ctx.clone()), &key, timeout_ms, from_peer)
                        .then(|res| ret.send(res))
                        .map_err(move |_| {
                            warn!("Completed RouterInfo lookup on {}, but client gave up", key)
                        }),
                );
            }
            Query::LookupLeaseSet(key, timeout_ms, from_local_dest, ret) => {
                spawn(
                    netdb
                        .write()
                        .unwrap()
                        .lookup_lease_set(Some(ctx.clone()), &key, timeout_ms, from_local_dest)
                        .then(|res| ret.send(res))
                        .map_err(move |_| {
                            warn!("Completed LeaseSet lookup on {}, but client gave up", key)
                        }),
                );
            }
        }
    }
}

pub struct KnownRouters {
    client: Client,
    response_rx: Option<oneshot::Receiver<usize>>,
}

impl KnownRouters {
    fn new(client: Client) -> Self {
        KnownRouters {
            client,
            response_rx: None,
        }
    }
}

impl Future for KnownRouters {
    type Item = usize;
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        if self.response_rx.is_none() {
            let (response_tx, response_rx) = oneshot::channel();
            self.response_rx = Some(response_rx);
            self.client.send(Query::KnownRouters(response_tx))?;
        }

        self.response_rx
            .as_mut()
            .unwrap()
            .poll()
            .map_err(|_| Error::Closed)
    }
}

pub struct SelectClosestFloodfill {
    client: Client,
    query: Option<Hash>,
    response_rx: Option<oneshot::Receiver<Option<RouterInfo>>>,
}

impl SelectClosestFloodfill {
    fn new(client: Client, key: Hash) -> Self {
        SelectClosestFloodfill {
            client,
            query: Some(key),
            response_rx: None,
        }
    }
}

impl Future for SelectClosestFloodfill {
    type Item = Option<RouterInfo>;
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        if let Some(key) = self.query.take() {
            let (response_tx, response_rx) = oneshot::channel();
            self.response_rx = Some(response_rx);
            self.client
                .send(Query::SelectClosestFloodfill(key, response_tx))?;
        }

        self.response_rx
            .as_mut()
            .unwrap()
            .poll()
            .map_err(|_| Error::Closed)
    }
}

pub struct LookupRouterInfo {
    client: Client,
    query: Option<(Hash, u64, Option<RouterInfo>)>,
    response_rx: Option<oneshot::Receiver<Result<RouterInfo, LookupError>>>,
}

impl LookupRouterInfo {
    fn new(client: Client, key: Hash, timeout_ms: u64, from_peer: Option<RouterInfo>) -> Self {
        LookupRouterInfo {
            client,
            query: Some((key, timeout_ms, from_peer)),
            response_rx: None,
        }
    }
}

impl Future for LookupRouterInfo {
    type Item = RouterInfo;
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        if let Some(query) = self.query.take() {
            let (response_tx, response_rx) = oneshot::channel();
            self.response_rx = Some(response_rx);
            self.client.send(Query::LookupRouterInfo(
                query.0,
                query.1,
                query.2,
                response_tx,
            ))?;
        }

        match self.response_rx.as_mut().unwrap().poll() {
            Ok(Async::Ready(Ok(ret))) => Ok(Async::Ready(ret)),
            Ok(Async::Ready(Err(e))) => Err(e.into()),
            Ok(Async::NotReady) => Ok(Async::NotReady),
            Err(_) => Err(Error::Closed),
        }
    }
}

pub struct LookupLeaseSet {
    client: Client,
    query: Option<(Hash, u64, Option<Hash>)>,
    response_rx: Option<oneshot::Receiver<Result<LeaseSet, LookupError>>>,
}

impl LookupLeaseSet {
    fn new(client: Client, key: Hash, timeout_ms: u64, from_local_dest: Option<Hash>) -> Self {
        LookupLeaseSet {
            client,
            query: Some((key, timeout_ms, from_local_dest)),
            response_rx: None,
        }
    }
}

impl Future for LookupLeaseSet {
    type Item = LeaseSet;
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        if let Some(query) = self.query.take() {
            let (response_tx, response_rx) = oneshot::channel();
            self.response_rx = Some(response_rx);
            self.client.send(Query::LookupLeaseSet(
                query.0,
                query.1,
                query.2,
                response_tx,
            ))?;
        }

        match self.response_rx.as_mut().unwrap().poll() {
            Ok(Async::Ready(Ok(ret))) => Ok(Async::Ready(ret)),
            Ok(Async::Ready(Err(e))) => Err(e.into()),
            Ok(Async::NotReady) => Ok(Async::NotReady),
            Err(_) => Err(Error::Closed),
        }
    }
}

#[derive(Clone)]
pub struct Client(Arc<mpsc::UnboundedSender<Query>>);

impl Client {
    pub fn new(client_tx: mpsc::UnboundedSender<Query>) -> Self {
        Client(Arc::new(client_tx))
    }

    fn send(&self, query: Query) -> Result<(), Error> {
        self.0.unbounded_send(query).map_err(|_| Error::Closed)
    }

    pub fn known_routers(&self) -> KnownRouters {
        KnownRouters::new(self.clone())
    }

    pub fn select_closest_ff(&self, key: Hash) -> SelectClosestFloodfill {
        SelectClosestFloodfill::new(self.clone(), key)
    }

    pub fn lookup_router_info(
        &self,
        key: Hash,
        timeout_ms: u64,
        from_peer: Option<RouterInfo>,
    ) -> LookupRouterInfo {
        LookupRouterInfo::new(self.clone(), key, timeout_ms, from_peer)
    }

    pub fn lookup_lease_set(
        &self,
        key: Hash,
        timeout_ms: u64,
        from_local_dest: Option<Hash>,
    ) -> LookupLeaseSet {
        LookupLeaseSet::new(self.clone(), key, timeout_ms, from_local_dest)
    }
}
