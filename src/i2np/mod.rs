//! Messages within the I2P network.
//!
//! The I2P Network Protocol (I2NP), which is sandwiched between I2CP and the
//! various I2P transport protocols, manages the routing and mixing of messages
//! between routers, as well as the selection of what transports to use when
//! communicating with a peer for which there are multiple common transports
//! supported.
//!
//! [I2NP specification](https://geti2p.net/spec/i2np)

use cookie_factory::GenError;
use nom::IResult;
use rand::{thread_rng, Rng};
use std::fmt;
use std::iter::repeat;
use std::time::{Duration, SystemTime};

use crypto::SessionKey;
use data::{Certificate, Hash, I2PDate, LeaseSet, RouterInfo, SessionTag, TunnelId};

#[allow(double_parens)]
#[allow(needless_pass_by_value)]
pub(crate) mod frame;

const MESSAGE_EXPIRATION_MS: u64 = 60 * 1000;

//
// Common structures
//

/// One record in a set of multiple records to request the creation of one hop
/// in the tunnel.
pub struct BuildRequestRecord {
    to_peer: Hash,
    receive_tid: TunnelId,
    our_ident: Hash,
    next_tid: TunnelId,
    next_ident: Hash,
    layer_key: SessionKey,
    iv_key: SessionKey,
    reply_key: SessionKey,
    reply_iv: [u8; 16],
    flag: u8,
    request_time: u32,
    send_msg_id: u32,
}

/// Reply to a BuildRequestRecord stating whether or not a particular hop agrees
/// to participate.
pub struct BuildResponseRecord {
    reply: u8,
}

//
// Messages
//

pub struct ReplyPath {
    token: u32,
    tid: TunnelId,
    gateway: Hash,
}

pub enum DatabaseStoreData {
    RI(RouterInfo),
    LS(LeaseSet),
}

/// An unsolicited database store, or the response to a successful DatabaseLookup
/// message.
pub struct DatabaseStore {
    pub key: Hash,
    ds_type: u8,
    reply: Option<ReplyPath>,
    pub data: DatabaseStoreData,
}

impl DatabaseStore {
    pub fn from_ri(ri: RouterInfo, reply: Option<ReplyPath>) -> Self {
        DatabaseStore {
            key: ri.router_id.hash(),
            ds_type: 0,
            reply,
            data: DatabaseStoreData::RI(ri),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum DatabaseLookupType {
    Any,
    LeaseSet,
    RouterInfo,
    Exploratory,
}

#[derive(Debug, PartialEq)]
struct DatabaseLookupFlags {
    delivery: bool,
    encryption: bool,
    lookup_type: DatabaseLookupType,
}

/// A request to look up an item in the network database. The response is either
/// a DatabaseStore or a DatabaseSearchReply.
pub struct DatabaseLookup {
    key: Hash,
    from: Hash,
    lookup_type: DatabaseLookupType,
    reply_tid: Option<TunnelId>,
    excluded_peers: Vec<Hash>,
    reply_enc: Option<(SessionKey, Vec<SessionTag>)>,
}

/// The response to a failed DatabaseLookup message, containing a list of router
/// hashes closest to the requested key.
pub struct DatabaseSearchReply {
    key: Hash,
    peers: Vec<Hash>,
    from: Hash,
}

/// A simple message acknowledgment. Generally created by the message originator,
/// and wrapped in a Garlic message with the message itself, to be returned by
/// the destination.
pub struct DeliveryStatus {
    msg_id: u32,
    time_stamp: I2PDate,
}

pub struct GarlicCloveDeliveryInstructions {
    encrypted: bool,
    delivery_type: u8,
    delay_set: bool,
    session_key: Option<SessionKey>,
    to_hash: Option<Hash>,
    tid: Option<TunnelId>,
    delay: Option<u32>,
}
pub struct GarlicClove {
    delivery_instructions: GarlicCloveDeliveryInstructions,
    msg: Message,
    clove_id: u32,
    expiration: I2PDate,
    cert: Certificate,
}

/// Used to wrap multiple encrypted I2NP messages.
pub struct Garlic {
    cloves: Vec<GarlicClove>,
    cert: Certificate,
    msg_id: u32,
    expiration: I2PDate,
}

/// A message sent from a tunnel's gateway or participant to the next participant
/// or endpoint. The data is of fixed length, containing I2NP messages that are
/// fragmented, batched, padded, and encrypted.
pub struct TunnelData {
    tid: TunnelId,
    data: [u8; 1024],
}

impl TunnelData {
    fn from(tid: TunnelId, data: &[u8; 1024]) -> Self {
        let mut x = [0u8; 1024];
        x.copy_from_slice(data);
        TunnelData { tid, data: x }
    }
}

/// Wraps another I2NP message to be sent into a tunnel at the tunnel's inbound
/// gateway.
pub struct TunnelGateway {
    tid: TunnelId,
    data: Vec<u8>,
}

pub enum MessagePayload {
    DatabaseStore(DatabaseStore),
    DatabaseLookup(DatabaseLookup),
    DatabaseSearchReply(DatabaseSearchReply),
    DeliveryStatus(DeliveryStatus),
    Garlic(Garlic),
    TunnelData(TunnelData),
    TunnelGateway(TunnelGateway),

    /// Used by Garlic messages and Garlic Cloves to wrap arbitrary data.
    Data(Vec<u8>),
    TunnelBuild([[u8; 528]; 8]),
    TunnelBuildReply([[u8; 528]; 8]),
    VariableTunnelBuild(Vec<[u8; 528]>),
    VariableTunnelBuildReply(Vec<[u8; 528]>),
}

impl fmt::Debug for MessagePayload {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            MessagePayload::DatabaseStore(ref ds) => {
                format!("DatabaseStore (key: {:?})", ds.key).fmt(formatter)
            }
            MessagePayload::DatabaseLookup(ref dl) => {
                format!("DatabaseLookup (key: {:?})", dl.key).fmt(formatter)
            }
            MessagePayload::DatabaseSearchReply(ref dsr) => {
                format!("DatabaseSearchReply (key: {:?})", dsr.key).fmt(formatter)
            }
            MessagePayload::DeliveryStatus(ref ds) => format!(
                "DeliveryStatus (mid: {:?}, ts: {:?})",
                ds.msg_id, ds.time_stamp
            ).fmt(formatter),
            MessagePayload::Garlic(_) => "Garlic".fmt(formatter),
            MessagePayload::TunnelData(ref td) => {
                format!("TunnelData (tid: {:?})", td.tid).fmt(formatter)
            }
            MessagePayload::TunnelGateway(ref tg) => {
                format!("TunnelGateway (tid: {:?})", tg.tid).fmt(formatter)
            }
            MessagePayload::Data(_) => "Data".fmt(formatter),
            MessagePayload::TunnelBuild(_) => "TunnelBuild".fmt(formatter),
            MessagePayload::TunnelBuildReply(_) => "TunnelBuildReply".fmt(formatter),
            MessagePayload::VariableTunnelBuild(_) => "VariableTunnelBuild".fmt(formatter),
            MessagePayload::VariableTunnelBuildReply(_) => {
                "VariableTunnelBuildReply".fmt(formatter)
            }
        }
    }
}

#[derive(Debug)]
pub struct Message {
    pub(crate) id: u32,
    pub(crate) expiration: I2PDate,
    pub(crate) payload: MessagePayload,
}

impl PartialEq for Message {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.expiration == other.expiration
    }
}

macro_rules! measure_size {
    ($gen_item:ident, $item:expr) => {{
        let size;
        let mut buf_len = 1024;
        let mut buf = vec![0; buf_len];
        loop {
            match frame::$gen_item((&mut buf, 0), $item) {
                Ok((_, sz)) => {
                    size = sz;
                    break;
                }
                Err(e) => match e {
                    GenError::BufferTooSmall(sz) => {
                        buf.extend(repeat(0).take(sz - buf_len));
                        buf_len = buf.len();
                    }
                    e => panic!("Couldn't serialize Message: {:?}", e),
                },
            }
        }
        size
    }};
}

impl Message {
    pub fn from_payload(payload: MessagePayload) -> Self {
        Message {
            id: thread_rng().gen(),
            expiration: I2PDate::from_system_time(
                SystemTime::now() + Duration::from_millis(MESSAGE_EXPIRATION_MS),
            ),
            payload,
        }
    }

    pub fn dummy_data() -> Self {
        Message {
            id: 0,
            expiration: I2PDate(0x123_4567_87c0),
            payload: MessagePayload::Data(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]),
        }
    }

    pub fn size(&self) -> usize {
        measure_size!(gen_message, self)
    }

    pub fn ntcp2_size(&self) -> usize {
        measure_size!(gen_ntcp2_message, self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::SystemTime;

    macro_rules! check_size {
        ($size_func:ident, $header_size:expr) => {{
            assert_eq!(Message::dummy_data().$size_func(), $header_size + 4 + 10);
            assert_eq!(
                Message::from_payload(MessagePayload::DeliveryStatus(DeliveryStatus {
                    msg_id: 0,
                    time_stamp: I2PDate::from_system_time(SystemTime::now())
                })).$size_func(),
                $header_size + 12
            );
        }};
    }

    #[test]
    fn message_size() {
        check_size!(size, 16)
    }

    #[test]
    fn message_ntcp2_size() {
        check_size!(ntcp2_size, 9)
    }
}
