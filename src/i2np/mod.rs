//! Messages within the I2P network.
//!
//! The I2P Network Protocol (I2NP), which is sandwiched between I2CP and the
//! various I2P transport protocols, manages the routing and mixing of messages
//! between routers, as well as the selection of what transports to use when
//! communicating with a peer for which there are multiple common transports
//! supported.
//!
//! [I2NP specification](https://geti2p.net/spec/i2np)

use nom;
use rand::{thread_rng, Rng};
use std::fmt;
use std::time::{Duration, SystemTime};

use crate::crypto::{self, elgamal, SessionKey};
use crate::data::{
    Certificate, Hash, I2PDate, LeaseSet, ReadError, RouterInfo, SessionTag, TunnelId,
};
use crate::util::serialize;

#[allow(double_parens)]
#[allow(needless_pass_by_value)]
pub(crate) mod frame;

const MESSAGE_EXPIRATION_MS: u64 = 60 * 1000;

/// BuildRequestRecord errors
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BuildRequestError {
    Crypto(crypto::Error),
    Read(ReadError),
}

impl From<crypto::Error> for BuildRequestError {
    fn from(e: crypto::Error) -> Self {
        BuildRequestError::Crypto(e)
    }
}

impl<T> From<nom::Err<T>> for BuildRequestError {
    fn from(e: nom::Err<T>) -> Self {
        BuildRequestError::Read(e.into())
    }
}

//
// Common structures
//

#[derive(Debug, PartialEq)]
enum ParticipantType {
    InboundGateway,
    Intermediate,
    OutboundEndpoint,
}

/// One record in a set of multiple records to request the creation of one hop
/// in the tunnel.
#[derive(Debug, PartialEq)]
pub struct BuildRequestRecord {
    receive_tid: TunnelId,
    our_ident: Hash,
    next_tid: TunnelId,
    next_ident: Hash,
    layer_key: SessionKey,
    iv_key: SessionKey,
    reply_key: SessionKey,
    reply_iv: [u8; 16],
    hop_type: ParticipantType,
    request_time: u32,
    send_msg_id: u32,
}

impl BuildRequestRecord {
    pub fn decrypt(ct: &[u8], decryptor: &elgamal::Decryptor) -> Result<Self, BuildRequestError> {
        let pt = decryptor.decrypt(&ct, false)?;
        let (_, brr) = frame::build_request_record(&pt)?;
        Ok(brr)
    }
}

/// Reply to a BuildRequestRecord stating whether or not a particular hop agrees
/// to participate.
#[derive(Debug, PartialEq)]
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

    pub fn from_ls(ls: LeaseSet, reply: Option<ReplyPath>) -> Self {
        DatabaseStore {
            key: ls.dest.hash(),
            ds_type: 1,
            reply,
            data: DatabaseStoreData::LS(ls),
        }
    }
}

#[cfg_attr(tarpaulin, skip)]
impl fmt::Display for DatabaseStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        format!("DatabaseStore\n key: {}\ntype: {}", self.key, self.ds_type).fmt(f)
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

impl DatabaseLookup {
    pub fn create_msg(key: Hash, from: Hash, lookup_type: DatabaseLookupType) -> Message {
        Message::from_payload(MessagePayload::DatabaseLookup(DatabaseLookup {
            key,
            from,
            lookup_type,
            reply_tid: None,
            excluded_peers: vec![],
            reply_enc: None,
        }))
    }
}

#[cfg_attr(tarpaulin, skip)]
impl fmt::Display for DatabaseLookup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        format!(
            "DatabaseLookup\n- key: {}\n- type: {:?}\n- excluded peers: [{}  ]",
            self.key,
            self.lookup_type,
            self.excluded_peers
                .iter()
                .map(|peer| format!("    {}", peer))
                .fold(String::new(), |acc, peer| if acc.is_empty() {
                    acc + &"\n" + &peer + &"\n"
                } else {
                    acc + &peer + &"\n"
                })
        )
        .fmt(f)
    }
}

/// The response to a failed DatabaseLookup message, containing a list of router
/// hashes closest to the requested key.
pub struct DatabaseSearchReply {
    pub key: Hash,
    pub peers: Vec<Hash>,
    pub from: Hash,
}

#[cfg_attr(tarpaulin, skip)]
impl fmt::Display for DatabaseSearchReply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        format!(
            "DatabaseSearchReply\n- key: {}\n- peers: [{}  ]\n- from: {}",
            self.key,
            self.peers.iter().map(|peer| format!("    {}", peer)).fold(
                String::new(),
                |acc, peer| if acc.is_empty() {
                    acc + &"\n" + &peer + &"\n"
                } else {
                    acc + &peer + &"\n"
                }
            ),
            self.from
        )
        .fmt(f)
    }
}

/// A simple message acknowledgment. Generally created by the message originator,
/// and wrapped in a Garlic message with the message itself, to be returned by
/// the destination.
pub struct DeliveryStatus {
    msg_id: u32,
    time_stamp: I2PDate,
}

#[cfg_attr(tarpaulin, skip)]
impl fmt::Display for DeliveryStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        format!(
            "DeliveryStatus\n- mid: {}\n- ts: {}",
            self.msg_id, self.time_stamp
        )
        .fmt(f)
    }
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

#[cfg_attr(tarpaulin, skip)]
impl fmt::Debug for MessagePayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
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
            )
            .fmt(formatter),
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

#[cfg_attr(tarpaulin, skip)]
impl fmt::Display for MessagePayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            MessagePayload::DatabaseStore(ref ds) => ds.fmt(formatter),
            MessagePayload::DatabaseLookup(ref dl) => dl.fmt(formatter),
            MessagePayload::DatabaseSearchReply(ref dsr) => dsr.fmt(formatter),
            MessagePayload::DeliveryStatus(ref ds) => ds.fmt(formatter),
            MessagePayload::Garlic(_) => "Garlic".fmt(formatter),
            MessagePayload::TunnelData(ref td) => {
                format!("TunnelData (tid: {})", td.tid).fmt(formatter)
            }
            MessagePayload::TunnelGateway(ref tg) => {
                format!("TunnelGateway (tid: {})", tg.tid).fmt(formatter)
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

#[cfg_attr(tarpaulin, skip)]
impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        format!(
            "Message ID: {}\nExpiration: {}\nPayload: {}",
            self.id, self.expiration, self.payload
        )
        .fmt(f)
    }
}

impl PartialEq for Message {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.expiration == other.expiration
    }
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
        serialize(|input| frame::gen_message(input, self)).len()
    }

    pub fn ntcp2_size(&self) -> usize {
        serialize(|input| frame::gen_ntcp2_message(input, self)).len()
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
                }))
                .$size_func(),
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
