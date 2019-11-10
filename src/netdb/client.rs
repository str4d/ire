//! An asynchronous NetDB client.

use futures::{
    sync::{mpsc, oneshot},
    Async, Future, Poll,
};
use std::sync::Arc;
use tokio::spawn;

use super::{errors::*, LocalNetworkDatabase};
use crate::data::{Hash, LeaseSet, RouterInfo};

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
    StoreRouterInfo(
        Hash,
        RouterInfo,
        bool,
        oneshot::Sender<Result<Option<RouterInfo>, StoreError>>,
    ),
    StoreLeaseSet(
        Hash,
        LeaseSet,
        oneshot::Sender<Result<Option<LeaseSet>, StoreError>>,
    ),
}

impl Query {
    pub(super) fn handle(self, netdb: &mut LocalNetworkDatabase) {
        match self {
            Query::KnownRouters(ret) => {
                if ret.send(netdb.known_routers()).is_err() {
                    warn!("Completed known routers query, but client gave up");
                }
            }
            Query::SelectClosestFloodfill(key, ret) => {
                if ret.send(netdb.select_closest_ff(&key)).is_err() {
                    warn!("Completed floodfill selection, but client gave up");
                }
            }
            Query::LookupRouterInfo(key, timeout_ms, from_peer, ret) => {
                spawn(
                    netdb
                        .lookup_router_info(&key, timeout_ms, from_peer)
                        .then(|res| ret.send(res))
                        .map_err(move |_| {
                            warn!("Completed RouterInfo lookup on {}, but client gave up", key)
                        }),
                );
            }
            Query::LookupLeaseSet(key, timeout_ms, from_local_dest, ret) => {
                spawn(
                    netdb
                        .lookup_lease_set(&key, timeout_ms, from_local_dest)
                        .then(|res| ret.send(res))
                        .map_err(move |_| {
                            warn!("Completed LeaseSet lookup on {}, but client gave up", key)
                        }),
                );
            }
            Query::StoreRouterInfo(key, ri, from_reseed, ret) => {
                if ret
                    .send(netdb.store_router_info(key.clone(), ri, from_reseed))
                    .is_err()
                {
                    warn!("Completed RouterInfo store at {}, but client gave up", key);
                }
            }
            Query::StoreLeaseSet(key, ls, ret) => {
                if ret.send(netdb.store_lease_set(key.clone(), ls)).is_err() {
                    warn!("Completed LeaseSet store at {}, but client gave up", key);
                }
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

pub struct StoreRouterInfo {
    client: Client,
    query: Option<(Hash, RouterInfo, bool)>,
    response_rx: Option<oneshot::Receiver<Result<Option<RouterInfo>, StoreError>>>,
}

impl StoreRouterInfo {
    fn new(client: Client, key: Hash, ri: RouterInfo, from_reseed: bool) -> Self {
        StoreRouterInfo {
            client,
            query: Some((key, ri, from_reseed)),
            response_rx: None,
        }
    }
}

impl Future for StoreRouterInfo {
    type Item = Option<RouterInfo>;
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        if let Some((key, ri, from_reseed)) = self.query.take() {
            let (response_tx, response_rx) = oneshot::channel();
            self.response_rx = Some(response_rx);
            self.client
                .send(Query::StoreRouterInfo(key, ri, from_reseed, response_tx))?;
        }

        match self.response_rx.as_mut().unwrap().poll() {
            Ok(Async::Ready(Ok(ret))) => Ok(Async::Ready(ret)),
            Ok(Async::Ready(Err(e))) => Err(e.into()),
            Ok(Async::NotReady) => Ok(Async::NotReady),
            Err(_) => Err(Error::Closed),
        }
    }
}

pub struct StoreLeaseSet {
    client: Client,
    query: Option<(Hash, LeaseSet)>,
    response_rx: Option<oneshot::Receiver<Result<Option<LeaseSet>, StoreError>>>,
}

impl StoreLeaseSet {
    fn new(client: Client, key: Hash, ls: LeaseSet) -> Self {
        StoreLeaseSet {
            client,
            query: Some((key, ls)),
            response_rx: None,
        }
    }
}

impl Future for StoreLeaseSet {
    type Item = Option<LeaseSet>;
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        if let Some((key, ls)) = self.query.take() {
            let (response_tx, response_rx) = oneshot::channel();
            self.response_rx = Some(response_rx);
            self.client
                .send(Query::StoreLeaseSet(key, ls, response_tx))?;
        }

        match self.response_rx.as_mut().unwrap().poll() {
            Ok(Async::Ready(Ok(ret))) => Ok(Async::Ready(ret)),
            Ok(Async::Ready(Err(e))) => Err(e.into()),
            Ok(Async::NotReady) => Ok(Async::NotReady),
            Err(_) => Err(Error::Closed),
        }
    }
}

/// A client for interacting with I2P's network database.
#[derive(Clone)]
pub struct Client(Arc<mpsc::UnboundedSender<Query>>);

impl Client {
    pub fn new(client_tx: mpsc::UnboundedSender<Query>) -> Self {
        Client(Arc::new(client_tx))
    }

    fn send(&self, query: Query) -> Result<(), Error> {
        self.0.unbounded_send(query).map_err(|_| Error::Closed)
    }

    /// Returns the number of RouterInfos that this database contains.
    pub fn known_routers(&self) -> KnownRouters {
        KnownRouters::new(self.clone())
    }

    /// Returns the closest floodfill router to the given netDb key.
    pub fn select_closest_ff(&self, key: Hash) -> SelectClosestFloodfill {
        SelectClosestFloodfill::new(self.clone(), key)
    }

    /// Finds the RouterInfo stored at the given key. A remote lookup will be performed if
    /// the key is not found locally.
    pub fn lookup_router_info(
        &self,
        key: Hash,
        timeout_ms: u64,
        from_peer: Option<RouterInfo>,
    ) -> LookupRouterInfo {
        LookupRouterInfo::new(self.clone(), key, timeout_ms, from_peer)
    }

    /// Finds the LeaseSet stored at the given key. If not known locally, the LeaseSet is
    /// looked up using the client tunnels for `from_local_dest` if provided, or
    /// exploratory tunnels otherwise.
    pub fn lookup_lease_set(
        &self,
        key: Hash,
        timeout_ms: u64,
        from_local_dest: Option<Hash>,
    ) -> LookupLeaseSet {
        LookupLeaseSet::new(self.clone(), key, timeout_ms, from_local_dest)
    }

    /// Stores a RouterInfo locally.
    ///
    /// Returns the RouterInfo that was previously at this key.
    pub fn store_router_info(
        &self,
        key: Hash,
        ri: RouterInfo,
        from_reseed: bool,
    ) -> StoreRouterInfo {
        StoreRouterInfo::new(self.clone(), key, ri, from_reseed)
    }

    /// Stores a LeaseSet locally.
    ///
    /// Returns the LeaseSet that was previously at this key.
    pub fn store_lease_set(&self, key: Hash, ls: LeaseSet) -> StoreLeaseSet {
        StoreLeaseSet::new(self.clone(), key, ls)
    }
}
