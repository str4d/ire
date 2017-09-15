use nom::IResult;

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
struct DatabaseStore {
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
struct DatabaseLookup {
    key: Hash,
    from: Hash,
    flags: DatabaseLookupFlags,
    reply_tid: Option<TunnelId>,
    excluded_peers: Vec<Hash>,
    reply_key: Option<SessionKey>,
    tags: Option<Vec<SessionTag>>,
}

struct DatabaseSearchReply {
    key: Hash,
    peers: Vec<Hash>,
    from: Hash,
}

struct DeliveryStatus {
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
struct Garlic {
    cloves: Vec<GarlicClove>,
    cert: Certificate,
    msg_id: u32,
    expiration: I2PDate,
}

struct TunnelData {
    tid: TunnelId,
    data: [u8; 1024],
}

impl TunnelData {
    fn from(tid: TunnelId, data: &[u8; 1024]) -> Self {
        let mut x = [0u8; 1024];
        x.copy_from_slice(data);
        TunnelData {
            tid: tid,
            data: x,
        }
    }
}

struct TunnelGateway {
    tid: TunnelId,
    data: Vec<u8>,
}

enum MessagePayload {
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

pub struct Message {
    id: u32,
    expiration: I2PDate,
    payload: MessagePayload,
}