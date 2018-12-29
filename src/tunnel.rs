//! Implementation of tunnels over I2P.

use std::time::SystemTime;

use crate::data::{Hash, RouterInfo, TunnelId};

mod acceptor;
mod encryption;
mod frame;
mod processor;

pub use self::acceptor::Listener;
pub use self::processor::Participant;

/// The lifetime of a tunnel. Always 10 minutes for current I2P tunnels.
const TUNNEL_LIFETIME: u64 = 10 * 60;

/// Data specific to the type of hop:
/// - InboundGateway contains `next_hop`
/// - Intermediate contains `from_ident` and `next_hop`
/// - OutboundEndpoint contains `from_ident`
enum HopData {
    InboundGateway((RouterInfo, TunnelId)),
    Intermediate(Hash, (RouterInfo, TunnelId)),
    OutboundEndpoint(Hash),
}

/// The configuration of a particular hop in a tunnel.
///
/// Tunnels have a maximum lifetime of 10 minutes, so the [`RouterInfo`] of the next hop
/// is looked up at tunnel build time and cached here.
pub struct HopConfig {
    hop_data: HopData,
    layer_cipher: encryption::LayerCipher,
    expires: SystemTime,
}

#[derive(Debug, PartialEq)]
enum TunnelMessageDeliveryType {
    Local,
    Tunnel(TunnelId, Hash),
    Router(Hash),
}

/// The delivery instructions included with the first fragment of an I2NP message, or an
/// unfragmented message.
///
/// The delay and extended options flag bits are not implemented.
#[derive(Debug, PartialEq)]
struct FirstFragmentDeliveryInstructions {
    delivery_type: TunnelMessageDeliveryType,
    msg_id: Option<u32>,
}

/// The delivery instructions included with the second and subsequent fragments of an I2NP
/// message.
#[derive(Debug, PartialEq)]
struct FollowOnFragmentDeliveryInstructions {
    fragment_number: u8,
    last_fragment: bool,
    msg_id: u32,
}

#[derive(Debug, PartialEq)]
enum TunnelMessageDeliveryInstructions {
    First(FirstFragmentDeliveryInstructions),
    FollowOn(FollowOnFragmentDeliveryInstructions),
}

impl TunnelMessageDeliveryInstructions {
    fn byte_len(&self) -> usize {
        match self {
            TunnelMessageDeliveryInstructions::First(di) => {
                let mut len = 1 + match di.delivery_type {
                    TunnelMessageDeliveryType::Local => 0,
                    TunnelMessageDeliveryType::Tunnel(_, _) => 36,
                    TunnelMessageDeliveryType::Router(_) => 32,
                };
                if di.msg_id.is_some() {
                    len += 4;
                }
                len
            }
            TunnelMessageDeliveryInstructions::FollowOn(_) => 5,
        }
    }
}

/// A set of I2NP message fragments that serializes to at most 1003 bytes.
/// Forms the plaintext inside an I2NP [`TunnelData`] message.
#[derive(Debug, PartialEq)]
struct TunnelMessage<'a>(Vec<(TunnelMessageDeliveryInstructions, &'a [u8])>);

impl<'a> TunnelMessage<'a> {
    fn byte_len(&self) -> usize {
        self.0.iter().fold(0, |acc, (tmdi, frag)| {
            acc + tmdi.byte_len() + 2 + frag.len()
        })
    }
}
