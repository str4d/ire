use std::net::SocketAddr;

pub struct Config {
    pub(super) router_keyfile: String,
    pub(super) ri_file: String,
    pub(super) ntcp_addr: SocketAddr,
    pub(super) ntcp2_addr: SocketAddr,
    pub(super) ntcp2_keyfile: String,
}

impl Config {
    pub fn new(
        router_keyfile: String,
        ri_file: String,
        ntcp_addr: SocketAddr,
        ntcp2_addr: SocketAddr,
        ntcp2_keyfile: String,
    ) -> Self {
        Config {
            router_keyfile,
            ri_file,
            ntcp_addr,
            ntcp2_addr,
            ntcp2_keyfile,
        }
    }
}
