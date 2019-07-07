//! Logic for processing incoming tunnel build requests.

use aes::{self, block_cipher_trait::generic_array::GenericArray as AesGenericArray};
use block_modes::{block_padding::ZeroPadding, BlockMode, BlockModeIv, Cbc};
use futures::{sink, sync::mpsc, try_ready, Async, Future, Poll, Sink, Stream};
use std::slice::IterMut;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio_executor::spawn;
use tokio_io::IoFuture;
use tokio_threadpool::blocking;

use super::{encryption::LayerCipher, HopConfig, HopData, TUNNEL_LIFETIME};
use crate::crypto::{elgamal, SessionKey};
use crate::data::{Hash, RouterInfo, TunnelId};
use crate::i2np::{
    frame::gen_build_response_record, BuildRequestError, BuildRequestRecord, BuildResponseRecord,
    Message, MessagePayload, ParticipantType,
};
use crate::netdb::client::LookupRouterInfo;
use crate::router::Context;
use crate::util::DecayingBloomFilter;

/// Build requests can be no more than 65 minutes older than the current time.
const MAX_REQUEST_AGE: u64 = 65 * 60;
/// Build requests can be no more than 5 minutes newer than the current time.
const MAX_REQUEST_FUTURE: u64 = 5 * 60;

/// The maximum time we will spend trying to look up the next peer in a tunnel we are
/// being asked to participate in.
const MAX_LOOKUP_TIME: u64 = 30;

const TUNNEL_ACCEPT: u8 = 0;
const TUNNEL_REJECT_PROBABALISTIC_REJECT: u8 = 10;
const TUNNEL_REJECT_TRANSIENT_OVERLOAD: u8 = 20;
const TUNNEL_REJECT_BANDWIDTH: u8 = 30;
const TUNNEL_REJECT_CRIT: u8 = 50;

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
                error!("Error while processing a build request: {}", e);
                return Err(());
            }
        }
    };
}

trait TunnelBuildRequest {
    fn entry_mut(&mut self, entry: usize) -> &mut [u8; 528];
    fn iter_mut(&mut self) -> IterMut<[u8; 528]>;
    fn to_msg(self, msg_id: u32) -> Message;
    fn to_reply(self, msg_id: u32) -> Message;
}

impl TunnelBuildRequest for [[u8; 528]; 8] {
    fn entry_mut(&mut self, entry: usize) -> &mut [u8; 528] {
        &mut self[entry]
    }

    fn iter_mut(&mut self) -> IterMut<[u8; 528]> {
        (&mut self[..]).iter_mut()
    }

    fn to_msg(self, msg_id: u32) -> Message {
        let mut msg = Message::from_payload(MessagePayload::TunnelBuild(self));
        msg.id = msg_id;
        msg
    }

    fn to_reply(self, msg_id: u32) -> Message {
        let mut msg = Message::from_payload(MessagePayload::TunnelBuildReply(self));
        msg.id = msg_id;
        msg
    }
}

impl TunnelBuildRequest for Vec<[u8; 528]> {
    fn entry_mut(&mut self, entry: usize) -> &mut [u8; 528] {
        &mut self[entry]
    }

    fn iter_mut(&mut self) -> IterMut<[u8; 528]> {
        (&mut self[..]).iter_mut()
    }

    fn to_msg(self, msg_id: u32) -> Message {
        let mut msg = Message::from_payload(MessagePayload::VariableTunnelBuild(self));
        msg.id = msg_id;
        msg
    }

    fn to_reply(self, msg_id: u32) -> Message {
        let mut msg = Message::from_payload(MessagePayload::VariableTunnelBuildReply(self));
        msg.id = msg_id;
        msg
    }
}

struct EncryptionInfo<TB: TunnelBuildRequest> {
    is_obep: bool,
    next_hop: RouterInfo,
    send_msg_id: u32,
    response: BuildResponseRecord,
    tb: TB,
    i: usize,
    reply_key: SessionKey,
    reply_iv: [u8; 16],
}

enum HopAcceptorState<TB: TunnelBuildRequest> {
    Decrypt(Hash, TB, usize),
    Resolving(Hash, LookupRouterInfo, BuildRequestRecord, TB, usize),
    RegisterParticipating(
        sink::Send<mpsc::Sender<(TunnelId, HopConfig)>>,
        EncryptionInfo<TB>,
    ),
    Encrypt(EncryptionInfo<TB>),
    Sending(IoFuture<()>),
}

/// A [`Future`] that processes a single tunnel build request.
///
/// Encryption operations are handled using the [`blocking`] threadpool.
struct HopAcceptor<TB: TunnelBuildRequest> {
    state: Option<HopAcceptorState<TB>>,
    decryptor: elgamal::Decryptor,
    filter: Arc<Mutex<DecayingBloomFilter>>,
    new_participating_tx: mpsc::Sender<(TunnelId, HopConfig)>,
    ctx: Arc<Context>,
}

impl<TB: TunnelBuildRequest> HopAcceptor<TB> {
    fn new(
        from: Hash,
        tb: TB,
        entry: usize,
        decryptor: elgamal::Decryptor,
        filter: Arc<Mutex<DecayingBloomFilter>>,
        new_participating_tx: mpsc::Sender<(TunnelId, HopConfig)>,
        ctx: Arc<Context>,
    ) -> Self {
        HopAcceptor {
            state: Some(HopAcceptorState::Decrypt(from, tb, entry)),
            decryptor,
            filter,
            new_participating_tx,
            ctx,
        }
    }
}

impl<TB: TunnelBuildRequest> Future for HopAcceptor<TB> {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<(), ()> {
        loop {
            let next_state = match self.state.take().unwrap() {
                HopAcceptorState::Decrypt(from_ident, mut tb, i) => {
                    // Attempt to decrypt the received TunnelBuildRequest
                    match try_poll!(
                        blocking(|| {
                            let brr =
                                BuildRequestRecord::decrypt(tb.entry_mut(i), &self.decryptor)?;
                            // Check for duplicates by feeding the reply key into a decaying
                            // Bloom filter.
                            if self.filter.lock().unwrap().feed(&brr.reply_key.0) {
                                Err(BuildRequestError::Duplicate)
                            } else {
                                Ok(brr)
                            }
                        }),
                        self,
                        HopAcceptorState::Decrypt(from_ident, tb, i)
                    ) {
                        Ok(brr) => {
                            // Validity checks. If any of these fail, we drop the request without
                            // any further processing or forwarding.

                            // Loop detection:
                            // - (A-A)
                            //   Don't allow ourselves to appear twice in a row within the tunnel.
                            if let ParticipantType::OutboundEndpoint = brr.hop_type {
                                // An OBEP has no subsequent peer, and we couldn't create a tunnel
                                // with it preceding itself without failing this check while setting
                                // up the preceding hop.
                            } else if brr.next_ident == self.ctx.keys.rid.hash() {
                                warn!("Dropping build request, we are the next hop: {:?}", brr);
                                return Ok(Async::Ready(()));
                            }
                            // - (A-B-A)
                            //   Don't allow the previous and next hops to be the same.
                            //   Obviously can't apply to IBGWs or OBEPs.
                            if let ParticipantType::Intermediate = brr.hop_type {
                                if from_ident == brr.next_ident {
                                    warn!("Dropping build request with the same previous and next hop: {:?}", brr);
                                    return Ok(Async::Ready(()));
                                }
                            }
                            // - (A-B-C-A)
                            //   We can't detect this (or any longer loops).

                            // Timestamp validity
                            let request_time =
                                Duration::from_secs(u64::from(brr.request_time) * 3600);
                            let cur_time = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .expect("System time is broken!");
                            if request_time < cur_time {
                                let time_diff = (cur_time - request_time).as_secs();
                                if time_diff > MAX_REQUEST_AGE {
                                    warn!(
                                        "Dropping build request too old; replay attack? ({}): {:?}",
                                        time_diff, brr
                                    );
                                    return Ok(Async::Ready(()));
                                }
                            } else {
                                let time_diff = (request_time - cur_time).as_secs();
                                if time_diff > MAX_REQUEST_FUTURE {
                                    warn!(
                                        "Dropping build request too far in future ({}): {:?}",
                                        time_diff, brr
                                    );
                                    return Ok(Async::Ready(()));
                                }
                            }

                            // Okay, this request looks legit.
                            // Look up the RouterInfo for the next peer in the tunnel
                            let f = self.ctx.netdb.lookup_router_info(
                                brr.next_ident.clone(),
                                MAX_LOOKUP_TIME * 1000,
                                None,
                            );
                            HopAcceptorState::Resolving(from_ident, f, brr, tb, i)
                        }
                        Err(_) => {
                            debug!("Couldn't decrypt build request, dropping");
                            return Ok(Async::Ready(()));
                        }
                    }
                }
                HopAcceptorState::Resolving(from_ident, mut f, brr, tb, i) => {
                    // Wait for the lookup to finish
                    let next_hop = try_poll!(
                        f.poll(),
                        self,
                        HopAcceptorState::Resolving(from_ident, f, brr, tb, i)
                    );

                    // Decide whether to accept or reject
                    // TODO: Add support for IBGW, OBEP, metrics
                    let reply = match brr.hop_type {
                        ParticipantType::Intermediate => TUNNEL_ACCEPT,
                        _ => TUNNEL_REJECT_CRIT,
                    };

                    // Prepare the information necessary to forward the response
                    let info = EncryptionInfo {
                        is_obep: brr.hop_type == ParticipantType::OutboundEndpoint,
                        next_hop: next_hop.clone(),
                        send_msg_id: brr.send_msg_id,
                        response: BuildResponseRecord { reply },
                        tb,
                        i,
                        reply_key: brr.reply_key,
                        reply_iv: brr.reply_iv,
                    };

                    if reply == TUNNEL_ACCEPT {
                        // We're committing to storing the following data in-memory for
                        // TUNNEL_LIFETIME seconds, and processing packets that match it.
                        let config = HopConfig {
                            hop_data: match brr.hop_type {
                                ParticipantType::InboundGateway => {
                                    HopData::InboundGateway((next_hop, brr.next_tid))
                                }
                                ParticipantType::Intermediate => {
                                    HopData::Intermediate(from_ident, (next_hop, brr.next_tid))
                                }
                                ParticipantType::OutboundEndpoint => {
                                    HopData::OutboundEndpoint(from_ident)
                                }
                            },
                            layer_cipher: LayerCipher::new(&brr.iv_key, brr.layer_key),
                            expires: SystemTime::now() + Duration::from_secs(TUNNEL_LIFETIME),
                        };

                        HopAcceptorState::RegisterParticipating(
                            self.new_participating_tx
                                .clone()
                                .send((brr.receive_tid, config)),
                            info,
                        )
                    } else {
                        // We declined to participate in the tunnel; just send our response onward.
                        HopAcceptorState::Encrypt(info)
                    }
                }
                HopAcceptorState::RegisterParticipating(mut f, info) => {
                    try_poll!(
                        f.poll(),
                        self,
                        HopAcceptorState::RegisterParticipating(f, info)
                    );
                    HopAcceptorState::Encrypt(info)
                }
                HopAcceptorState::Encrypt(mut info) => {
                    try_poll!(
                        blocking(|| {
                            // Write our response
                            {
                                let tb_entry = info.tb.entry_mut(info.i);
                                gen_build_response_record((tb_entry, 0), &info.response)
                                    .expect("Should not fail!");
                            }

                            // Now encrypt all the entries
                            for tb_entry in info.tb.iter_mut() {
                                let mut cipher: Cbc<aes::Aes256, ZeroPadding> = Cbc::new_fixkey(
                                    AesGenericArray::from_slice(&info.reply_key.0),
                                    AesGenericArray::from_slice(&info.reply_iv),
                                );
                                cipher.encrypt_nopad(tb_entry).expect("Should not fail!");
                            }
                        }),
                        self,
                        HopAcceptorState::Encrypt(info)
                    );

                    // If we are the OBEP in the build request, repackage it as a reply; otherwise,
                    // leave it as-is.
                    let msg = if info.is_obep {
                        info.tb.to_reply(info.send_msg_id)
                    } else {
                        info.tb.to_msg(info.send_msg_id)
                    };

                    // Forward the processed build request onto the next hop
                    match self.ctx.comms.read().unwrap().send(info.next_hop, msg) {
                        Ok(f) => HopAcceptorState::Sending(f),
                        Err((ri, _)) => {
                            error!(
                                "Could not forward build request to {} over any of our transports, dropping",
                                ri.router_id.hash()
                            );
                            return Err(());
                        }
                    }
                }
                HopAcceptorState::Sending(mut f) => {
                    try_poll!(f.poll(), self, HopAcceptorState::Sending(f));
                    return Ok(Async::Ready(()));
                }
            };
            self.state = Some(next_state);
        }
    }
}

/// A [`Future`] that handles incoming tunnel build requests.
///
/// Each build request is spawned into its own task, which uses the [`blocking`]
/// threadpool for encryption operations.
///
/// Currently the listener accepts every request for an intermediate position, and rejects
/// every IBGW and OBEP request.
pub struct Listener {
    our_hash: Hash,
    decryptor: elgamal::Decryptor,
    filter: Arc<Mutex<DecayingBloomFilter>>,
    new_participating_tx: mpsc::Sender<(TunnelId, HopConfig)>,
    ib_rx: mpsc::Receiver<(Hash, Message)>,
    ctx: Arc<Context>,
}

impl Listener {
    pub fn new(
        ctx: Arc<Context>,
        new_participating_tx: mpsc::Sender<(TunnelId, HopConfig)>,
        ib_rx: mpsc::Receiver<(Hash, Message)>,
    ) -> Self {
        Listener {
            our_hash: ctx.keys.rid.hash(),
            decryptor: elgamal::Decryptor::from(&ctx.keys.private_key),
            filter: Arc::new(Mutex::new(DecayingBloomFilter::new(20_000))),
            new_participating_tx,
            ib_rx,
            ctx,
        }
    }

    fn find_our_entry(&self, tb: &[[u8; 528]]) -> Option<usize> {
        for (i, tb_entry) in tb.iter().enumerate() {
            if tb_entry[0..16] == self.our_hash.0[0..16] {
                return Some(i);
            }
        }
        None
    }
}

impl Future for Listener {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<(), ()> {
        loop {
            // Process the next message
            if let Some((from, msg)) = try_ready!(self.ib_rx.poll()) {
                match msg.payload {
                    MessagePayload::TunnelBuild(tb) => {
                        if let Some(i) = self.find_our_entry(&tb) {
                            // Let's try to accept it
                            spawn(HopAcceptor::new(
                                from,
                                tb,
                                i,
                                self.decryptor.clone(),
                                self.filter.clone(),
                                self.new_participating_tx.clone(),
                                self.ctx.clone(),
                            ));
                        }
                    }
                    MessagePayload::VariableTunnelBuild(vtb) => {
                        if let Some(i) = self.find_our_entry(&vtb) {
                            // Let's try to accept it
                            spawn(HopAcceptor::new(
                                from,
                                vtb,
                                i,
                                self.decryptor.clone(),
                                self.filter.clone(),
                                self.new_participating_tx.clone(),
                                self.ctx.clone(),
                            ));
                        }
                    }
                    _ => {
                        debug!("Received unexpected message from {}:\n{}", from, msg);
                    }
                }
            } else {
                // Distributor has gone, we are done
                return Ok(Async::Ready(()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use futures::{lazy, sync::mpsc, Async, Future, Stream};
    use std::sync::{Arc, Mutex};
    use tokio_threadpool::Builder;

    use super::HopAcceptor;
    use crate::{
        crypto::elgamal,
        data::{Hash, RouterInfo, RouterSecretKeys, TunnelId},
        i2np::{BuildRequestRecord, ParticipantType},
        router::mock::{mock_context, mock_context_and_netdb},
        tunnel::HopData,
        util::DecayingBloomFilter,
    };

    #[test]
    #[ignore]
    fn accepted_intermediate_build_request() {
        let (ctx, mut netdb) = mock_context_and_netdb();

        let decryptor = elgamal::Decryptor::from(&ctx.keys.private_key);
        let filter = Arc::new(Mutex::new(DecayingBloomFilter::new(10)));
        let (new_participating_tx, mut new_participating_rx) = mpsc::channel(1);

        // Generate a peer to go before us
        let from_tid = TunnelId(1);
        let from_ident = Hash([1; 32]);

        // Generate a peer to go after us
        let next_tid = TunnelId(2);
        let next_ri = {
            let keys = RouterSecretKeys::new();
            let mut ri = RouterInfo::new(keys.rid);
            ri.sign(&keys.signing_private_key);
            ri
        };
        let next_ident = next_ri.router_id.hash();

        // Create a valid VariableTunnelBuild message
        let tb = {
            let brr = BuildRequestRecord::new(
                from_tid,
                ctx.keys.rid.hash(),
                next_tid,
                next_ident.clone(),
                ParticipantType::Intermediate,
            );
            vec![brr.encrypt(&elgamal::Encryptor::from(&ctx.keys.rid.public_key))]
        };

        // Add the next hop to the NetDB
        netdb.store_router_info(next_ident, next_ri.clone());

        let f = HopAcceptor::new(
            from_ident.clone(),
            tb,
            0,
            decryptor,
            filter,
            new_participating_tx,
            ctx,
        );

        // Run the acceptor on a threadpool
        let pool = Builder::new().pool_size(2).max_blocking(1).build();
        let mut res = pool.spawn_handle(f);

        // The acceptor should be waiting on the NetDB
        lazy(|| {
            assert_eq!(res.poll(), Ok(Async::NotReady));
            Ok::<(), ()>(())
        })
        .wait()
        .unwrap();

        // Start the NetDB
        pool.spawn(netdb);

        // The acceptor should now run to completion
        assert_eq!(res.wait(), Ok(()));

        // Shut down the threadpool, so that the test will not hang if subsequent
        // assertions fail.
        pool.shutdown_now().wait().unwrap();

        // We should have accepted the build request
        match new_participating_rx.poll() {
            Ok(Async::Ready(Some((receive_tid, config)))) => {
                assert_eq!(receive_tid, from_tid);
                assert_eq!(
                    config.hop_data,
                    HopData::Intermediate(from_ident, (next_ri, next_tid))
                )
            }
            v => panic!("Unexpected returned value: {:?}", v),
        }
    }

    #[test]
    #[ignore]
    fn build_request_loop_detection_adjacent() {
        let ctx = mock_context();

        let decryptor = elgamal::Decryptor::from(&ctx.keys.private_key);
        let filter = Arc::new(Mutex::new(DecayingBloomFilter::new(10)));
        let (new_participating_tx, mut new_participating_rx) = mpsc::channel(1);

        // Generate a peer to go before us
        let from_tid = TunnelId(1);
        let from_ident = Hash([1; 32]);

        // Try to use ourselves as the next hop
        let next_tid = TunnelId(2);
        let next_ident = ctx.keys.rid.hash();

        let tb = {
            let brr = BuildRequestRecord::new(
                from_tid,
                ctx.keys.rid.hash(),
                next_tid,
                next_ident,
                ParticipantType::Intermediate,
            );
            vec![brr.encrypt(&elgamal::Encryptor::from(&ctx.keys.rid.public_key))]
        };

        let f = HopAcceptor::new(
            from_ident.clone(),
            tb,
            0,
            decryptor,
            filter,
            new_participating_tx,
            ctx,
        );

        // The acceptor should run to completion without needing a NetDB lookup
        let pool = Builder::new().pool_size(2).max_blocking(1).build();
        assert_eq!(pool.spawn_handle(f).wait(), Ok(()));

        // Shut down the threadpool, so that the test will not hang if subsequent
        // assertions fail.
        pool.shutdown_now().wait().unwrap();

        // We should have not accepted the build request
        assert_eq!(new_participating_rx.poll(), Ok(Async::Ready(None)));
    }

    #[test]
    #[ignore]
    fn build_request_loop_detection_cycle() {
        let ctx = mock_context();

        let decryptor = elgamal::Decryptor::from(&ctx.keys.private_key);
        let filter = Arc::new(Mutex::new(DecayingBloomFilter::new(10)));
        let (new_participating_tx, mut new_participating_rx) = mpsc::channel(1);

        // Generate a peer to go before us
        let from_tid = TunnelId(1);
        let from_ident = Hash([1; 32]);

        // Try to use the same peer as the next hop
        let next_tid = TunnelId(2);
        let next_ident = from_ident.clone();

        let tb = {
            let brr = BuildRequestRecord::new(
                from_tid,
                ctx.keys.rid.hash(),
                next_tid,
                next_ident,
                ParticipantType::Intermediate,
            );
            vec![brr.encrypt(&elgamal::Encryptor::from(&ctx.keys.rid.public_key))]
        };

        let f = HopAcceptor::new(
            from_ident.clone(),
            tb,
            0,
            decryptor,
            filter,
            new_participating_tx,
            ctx,
        );

        // The acceptor should run to completion without needing a NetDB lookup
        let pool = Builder::new().pool_size(2).max_blocking(1).build();
        assert_eq!(pool.spawn_handle(f).wait(), Ok(()));

        // Shut down the threadpool, so that the test will not hang if subsequent
        // assertions fail.
        pool.shutdown_now().wait().unwrap();

        // We should have not accepted the build request
        assert_eq!(new_participating_rx.poll(), Ok(Async::Ready(None)));
    }
}
