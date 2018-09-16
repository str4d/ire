use std::net::SocketAddr;

pub struct Config {
    pub(super) router_keyfile: String,
    pub(super) ntcp_addr: SocketAddr,
    pub(super) ntcp2_addr: SocketAddr,
    pub(super) ntcp2_keyfile: String,
}

impl Config {
    pub fn new(
        router_keyfile: String,
        ntcp_addr: SocketAddr,
        ntcp2_addr: SocketAddr,
        ntcp2_keyfile: String,
    ) -> Self {
        Config {
            router_keyfile,
            ntcp_addr,
            ntcp2_addr,
            ntcp2_keyfile,
        }
    }
}
