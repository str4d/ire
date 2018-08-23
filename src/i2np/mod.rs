use nom::IResult;
use std::fmt;
use std::time::SystemTime;

use crypto::SessionKey;
use data::{Certificate, Hash, I2PDate, LeaseSet, RouterInfo, SessionTag, TunnelId};

pub mod frame;

//
// Common structures
//

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
pub struct BuildResponseRecord {
    reply: u8,
}

//
// Messages
//

struct ReplyPath {
    token: u32,
    tid: TunnelId,
    gateway: Hash,
}
enum DatabaseStoreData {
    RI(RouterInfo),
    LS(LeaseSet),
}
pub(crate) struct DatabaseStore {
    key: Hash,
    ds_type: u8,
    reply: Option<ReplyPath>,
    data: DatabaseStoreData,
}

struct DatabaseLookupFlags {
    delivery: bool,
    encryption: bool,
    lookup_type: u8,
}
pub(crate) struct DatabaseLookup {
    key: Hash,
    from: Hash,
    flags: DatabaseLookupFlags,
    reply_tid: Option<TunnelId>,
    excluded_peers: Vec<Hash>,
    reply_key: Option<SessionKey>,
    tags: Option<Vec<SessionTag>>,
}

pub(crate) struct DatabaseSearchReply {
    key: Hash,
    peers: Vec<Hash>,
    from: Hash,
}

pub(crate) struct DeliveryStatus {
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
pub(crate) struct Garlic {
    cloves: Vec<GarlicClove>,
    cert: Certificate,
    msg_id: u32,
    expiration: I2PDate,
}

pub(crate) struct TunnelData {
    tid: TunnelId,
    data: [u8; 1024],
}

impl TunnelData {
    fn from(tid: TunnelId, data: &[u8; 1024]) -> Self {
        let mut x = [0u8; 1024];
        x.copy_from_slice(data);
        TunnelData { tid: tid, data: x }
    }
}

pub(crate) struct TunnelGateway {
    tid: TunnelId,
    data: Vec<u8>,
}

pub(crate) enum MessagePayload {
    DatabaseStore(DatabaseStore),
    DatabaseLookup(DatabaseLookup),
    DatabaseSearchReply(DatabaseSearchReply),
    DeliveryStatus(DeliveryStatus),
    Garlic(Garlic),
    TunnelData(TunnelData),
    TunnelGateway(TunnelGateway),
    Data(Vec<u8>),
    TunnelBuild([[u8; 528]; 8]),
    TunnelBuildReply([[u8; 528]; 8]),
    VariableTunnelBuild(Vec<[u8; 528]>),
    VariableTunnelBuildReply(Vec<[u8; 528]>),
}

impl fmt::Debug for MessagePayload {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &MessagePayload::DatabaseStore(ref ds) => {
                format!("DatabaseStore (key: {:?})", ds.key).fmt(formatter)
            }
            &MessagePayload::DatabaseLookup(ref dl) => {
                format!("DatabaseLookup (key: {:?})", dl.key).fmt(formatter)
            }
            &MessagePayload::DatabaseSearchReply(ref dsr) => {
                format!("DatabaseSearchReply (key: {:?})", dsr.key).fmt(formatter)
            }
            &MessagePayload::DeliveryStatus(ref ds) => format!(
                "DeliveryStatus (mid: {:?}, ts: {:?})",
                ds.msg_id, ds.time_stamp
            ).fmt(formatter),
            &MessagePayload::Garlic(_) => "Garlic".fmt(formatter),
            &MessagePayload::TunnelData(ref td) => {
                format!("TunnelData (tid: {:?})", td.tid).fmt(formatter)
            }
            &MessagePayload::TunnelGateway(ref tg) => {
                format!("TunnelGateway (tid: {:?})", tg.tid).fmt(formatter)
            }
            &MessagePayload::Data(_) => "Data".fmt(formatter),
            &MessagePayload::TunnelBuild(_) => "TunnelBuild".fmt(formatter),
            &MessagePayload::TunnelBuildReply(_) => "TunnelBuildReply".fmt(formatter),
            &MessagePayload::VariableTunnelBuild(_) => "VariableTunnelBuild".fmt(formatter),
            &MessagePayload::VariableTunnelBuildReply(_) => {
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

impl Message {
    pub fn dummy_data() -> Self {
        Message {
            id: 0,
            expiration: I2PDate::from_system_time(SystemTime::now()),
            payload: MessagePayload::Data(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]),
        }
    }
}
