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

impl Default for Config {
    fn default() -> Self {
        // TODO: Real defaults
        Config {
            router_keyfile: "router.keys.dat".to_owned(),
            ri_file: "router.info".to_owned(),
            ntcp_addr: "127.0.0.1:0".parse().unwrap(),
            ntcp2_addr: "127.0.0.1:0".parse().unwrap(),
            ntcp2_keyfile: "router.ntcp2.keys.dat".to_owned(),
        }
    }
}
