//! Various datatypes common to all I2P protocols.
//!
//! [Common structures specification](https://geti2p.net/spec/common-structures)

use chrono::{DateTime, Utc};
use nom::{self, Needed};
use rand::{rngs::OsRng, Rng};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::constants;
use crate::crypto::{
    self, elgamal, EncType, PrivateKey, PublicKey, SigType, Signature, SigningPrivateKey,
    SigningPublicKey,
};
use crate::util::{fmt_colon_delimited_hex, serialize};

pub mod dest;

#[allow(needless_pass_by_value)]
pub(crate) mod frame;

pub use self::dest::{Destination, Lease, LeaseSet};

lazy_static! {
    pub(crate) static ref OPT_NET_ID: I2PString = "netId".into();
    static ref OPT_ROUTER_VERSION: I2PString = "router.version".into();
    static ref OPT_CAPS: I2PString = "caps".into();
}

lazy_static! {
    pub static ref NET_ID: I2PString = "2".into();
    static ref ROUTER_VERSION: I2PString = "0.9.37".into();
    static ref CAPS: I2PString = "KU".into();
}

/// Data read errors
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadError {
    FileIo(String),
    Incomplete(Needed),
    Parser,
}

#[cfg_attr(tarpaulin, skip)]
impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReadError::FileIo(e) => format!("File IO error: {}", e).fmt(f),
            ReadError::Incomplete(n) => format!("Data is incomplete (needed: {:?})", n).fmt(f),
            ReadError::Parser => "Parser error".fmt(f),
        }
    }
}

impl From<io::Error> for ReadError {
    fn from(e: io::Error) -> Self {
        ReadError::FileIo(format!("{}", e))
    }
}

impl<T> From<nom::Err<T>> for ReadError {
    fn from(e: nom::Err<T>) -> Self {
        match e {
            nom::Err::Incomplete(n) => ReadError::Incomplete(n),
            _ => ReadError::Parser,
        }
    }
}

//
// Simple data types
//

/// The SHA-256 hash of some data.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    pub fn from_bytes(buf: &[u8; 32]) -> Self {
        let mut x = [0u8; 32];
        x.copy_from_slice(buf);
        Hash(x)
    }

    pub fn digest(buf: &[u8]) -> Self {
        let mut hasher = Sha256::default();
        hasher.input(buf);
        let hash = hasher.result();
        Hash::from_bytes(array_ref![hash.as_slice(), 0, 32])
    }

    pub fn xor(&mut self, other: &Hash) {
        for i in 0..32 {
            self.0[i] ^= other.0[i];
        }
    }
}

#[cfg_attr(tarpaulin, skip)]
impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "Hash(")?;
        fmt_colon_delimited_hex(f, &self.0[..])?;
        write!(f, ")")
    }
}

#[cfg_attr(tarpaulin, skip)]
impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", constants::I2P_BASE64.encode(&self.0))
    }
}

/// The number of milliseconds since midnight on January 1, 1970 in the GMT
/// timezone. If the number is 0, the date is undefined or null.
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
pub struct I2PDate(pub(crate) u64);

impl I2PDate {
    pub fn from_system_time(t: SystemTime) -> Self {
        let d = t
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::new(0, 0));
        I2PDate(d.as_secs() * 1_000 + u64::from(d.subsec_millis()))
    }

    pub fn to_system_time(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_millis(self.0)
    }
}

#[cfg_attr(tarpaulin, skip)]
impl fmt::Display for I2PDate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        DateTime::<Utc>::from(self.to_system_time()).fmt(f)
    }
}

/// A UTF-8-encoded string.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct I2PString(pub String);

impl I2PString {
    pub fn new(string: &str) -> Self {
        I2PString(String::from(string))
    }

    pub fn to_csv(&self) -> Vec<Self> {
        self.0.split(',').map(|s| Self::new(s)).collect()
    }
}

impl<'a> From<&'a str> for I2PString {
    fn from(a: &'a str) -> Self {
        I2PString::new(a)
    }
}

/// A set of key/value mappings or properties.
#[derive(Clone, Debug, PartialEq)]
pub struct Mapping(pub HashMap<I2PString, I2PString>);

/// A random number.
pub struct SessionTag(pub [u8; 32]);

impl SessionTag {
    fn from_bytes(buf: &[u8; 32]) -> Self {
        let mut x = [0u8; 32];
        x.copy_from_slice(buf);
        SessionTag(x)
    }
}

/// Defines an identifier that is unique to each router in a tunnel. A TunnelId
/// is generally greater than zero; do not use a value of zero except in
/// special cases.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TunnelId(pub u32);

#[cfg_attr(tarpaulin, skip)]
impl fmt::Display for TunnelId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// A key certificate provides a mechanism to indicate the type of the PublicKey
/// and SigningPublicKey in the Destination or RouterIdentity, and to package
/// any key data in excess of the standard lengths.
///
/// By maintaining exactly 384 bytes before the certificate, and putting any
/// excess key data inside the certificate, we maintain compatibility for any
/// software that parses Destinations and RouterIdentities.
#[derive(Clone, Debug, PartialEq)]
pub struct KeyCertificate {
    pub sig_type: SigType,
    enc_type: EncType,
    sig_data: Vec<u8>,
    enc_data: Vec<u8>,
}

/// A container for various receipts or proof of works used throughout the I2P
/// network.
#[derive(Clone, Debug, PartialEq)]
pub enum Certificate {
    Null,
    HashCash(Vec<u8>),
    Hidden,
    Signed(Vec<u8>),
    Multiple(Vec<u8>),
    Key(KeyCertificate),
}

impl Certificate {
    pub fn code(&self) -> u8 {
        match *self {
            Certificate::Null => constants::NULL_CERT,
            Certificate::HashCash(_) => constants::HASH_CERT,
            Certificate::Hidden => constants::HIDDEN_CERT,
            Certificate::Signed(_) => constants::SIGNED_CERT,
            Certificate::Multiple(_) => constants::MULTI_CERT,
            Certificate::Key(_) => constants::KEY_CERT,
        }
    }
}

#[derive(Clone, PartialEq)]
pub(crate) struct Padding(Vec<u8>);

#[cfg_attr(tarpaulin, skip)]
impl fmt::Debug for Padding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "Padding(")?;
        fmt_colon_delimited_hex(f, &self.0[..])?;
        write!(f, ")")
    }
}

fn cert_and_padding_from_keys(
    _public_key: &PublicKey,
    signing_key: &SigningPublicKey,
) -> (Certificate, Option<Padding>) {
    let certificate = match signing_key.sig_type() {
        SigType::DsaSha1 => Certificate::Null,
        SigType::Ed25519 => Certificate::Key(KeyCertificate {
            sig_type: SigType::Ed25519,
            enc_type: EncType::ElGamal2048,
            sig_data: vec![],
            enc_data: vec![],
        }),
        _ => panic!("Not implemented!"),
    };
    let padding = match signing_key.sig_type().pad_len(EncType::ElGamal2048) {
        0 => None,
        sz => {
            let mut rng = OsRng::new().expect("should be able to construct RNG");
            let mut padding = Vec::new();
            padding.resize(sz, 0);
            rng.fill(&mut padding[..]);
            Some(Padding(padding))
        }
    };
    (certificate, padding)
}

/// Defines the way to uniquely identify a particular router.
#[derive(Clone, Debug, PartialEq)]
pub struct RouterIdentity {
    public_key: PublicKey,
    padding: Option<Padding>,
    pub signing_key: SigningPublicKey,
    pub certificate: Certificate,
}

impl RouterIdentity {
    pub fn from_file(path: &str) -> Result<Self, ReadError> {
        let mut rid = File::open(path)?;
        let mut data: Vec<u8> = Vec::new();
        rid.read_to_end(&mut data)?;
        let (_, res) = frame::router_identity(&data[..])?;
        Ok(res)
    }

    fn from_keys(public_key: PublicKey, signing_key: SigningPublicKey) -> Self {
        let (certificate, padding) = cert_and_padding_from_keys(&public_key, &signing_key);
        RouterIdentity {
            public_key,
            padding,
            signing_key,
            certificate,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serialize(|input| frame::gen_router_identity(input, self))
    }

    pub fn to_file(&self, path: &str) -> io::Result<()> {
        let mut rid = File::create(path)?;
        rid.write(&self.to_bytes()).map(|_| ())
    }

    pub fn hash(&self) -> Hash {
        Hash::digest(&self.to_bytes()[..])
    }
}

/// Key material for a RouterIdentity.
#[derive(Clone)]
pub struct RouterSecretKeys {
    pub rid: RouterIdentity,
    private_key: PrivateKey,
    pub signing_private_key: SigningPrivateKey,
}

impl RouterSecretKeys {
    pub fn new() -> Self {
        let (private_key, public_key) = elgamal::KeyPairGenerator::generate();
        let signing_private_key = SigningPrivateKey::new();
        let signing_key = SigningPublicKey::from_secret(&signing_private_key).unwrap();
        RouterSecretKeys {
            rid: RouterIdentity::from_keys(public_key, signing_key),
            private_key,
            signing_private_key,
        }
    }

    pub fn from_file(path: &str) -> Result<Self, ReadError> {
        let mut rsk = File::open(path)?;
        let mut data: Vec<u8> = Vec::new();
        rsk.read_to_end(&mut data)?;
        let (_, res) = frame::router_secret_keys(&data[..])?;
        Ok(res)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serialize(|input| frame::gen_router_secret_keys(input, self))
    }

    pub fn to_file(&self, path: &str) -> io::Result<()> {
        let mut rid = File::create(path)?;
        rid.write(&self.to_bytes()).map(|_| ())
    }
}

/// Defines the means to contact a router through a transport protocol.
#[derive(Clone, Debug, PartialEq)]
pub struct RouterAddress {
    cost: u8,
    expiration: I2PDate,
    transport_style: I2PString,
    options: Mapping,
}

impl RouterAddress {
    pub fn new(transport_style: &I2PString, addr: SocketAddr) -> Self {
        let mut options = HashMap::new();
        options.insert(
            I2PString(String::from("host")),
            I2PString(addr.ip().to_string()),
        );
        options.insert(
            I2PString(String::from("port")),
            I2PString(addr.port().to_string()),
        );
        RouterAddress {
            cost: 0,
            expiration: I2PDate(0),
            transport_style: transport_style.clone(),
            options: Mapping(options),
        }
    }

    pub fn option(&self, key: &I2PString) -> Option<&I2PString> {
        self.options.0.get(key)
    }

    pub fn set_option(&mut self, key: I2PString, value: I2PString) {
        self.options.0.insert(key, value);
    }

    pub fn addr(&self) -> Option<SocketAddr> {
        let host = self.options.0.get(&I2PString(String::from("host")));
        let port = self.options.0.get(&I2PString(String::from("port")));
        match (host, port) {
            (Some(host), Some(port)) => match (host.0.parse(), port.0.parse()) {
                (Ok(ip), Ok(port)) => Some(SocketAddr::new(ip, port)),
                _ => None,
            },
            _ => None,
        }
    }
}

/// Defines all of the data that a router wants to publish for the network to
/// see.
///
/// The RouterInfo is one of two structures stored in the network database (the
/// other being LeaseSet), and is keyed under the SHA-256 of the contained
/// RouterIdentity.
#[derive(Clone, Debug, PartialEq)]
pub struct RouterInfo {
    pub router_id: RouterIdentity,
    pub published: I2PDate,
    addresses: Vec<RouterAddress>,
    peers: Vec<Hash>,
    pub(crate) options: Mapping,
    signature: Option<Signature>,
}

impl RouterInfo {
    pub fn new(rid: RouterIdentity) -> Self {
        let mut options: HashMap<I2PString, I2PString> = HashMap::new();
        options.insert(OPT_NET_ID.clone(), NET_ID.clone());
        options.insert(OPT_ROUTER_VERSION.clone(), ROUTER_VERSION.clone());
        options.insert(OPT_CAPS.clone(), CAPS.clone());

        RouterInfo {
            router_id: rid,
            published: I2PDate::from_system_time(SystemTime::now()),
            addresses: Vec::new(),
            peers: Vec::new(),
            options: Mapping(options),
            signature: None,
        }
    }

    /// Set the addresses in this RouterInfo.
    ///
    /// Caller must re-sign the RouterInfo afterwards.
    pub fn set_addresses(&mut self, addrs: Vec<RouterAddress>) {
        self.addresses = addrs;
        self.signature = None;
    }

    pub fn address<F>(&self, style: &I2PString, filter: F) -> Option<RouterAddress>
    where
        F: Fn(&RouterAddress) -> bool,
    {
        self.addresses
            .iter()
            .filter(|a| a.transport_style == *style)
            .filter(|a| match a.addr() {
                Some(addr) => addr.is_ipv4(),
                None => false,
            })
            .find(|a| filter(a))
            .map(|a| (*a).clone())
    }

    pub fn network_id(&self) -> Option<&I2PString> {
        self.options.0.get(&OPT_NET_ID)
    }

    pub fn is_floodfill(&self) -> bool {
        self.options
            .0
            .get(&OPT_CAPS)
            .map(|caps| caps.0.contains('f'))
            .unwrap_or(false)
    }

    pub fn from_file(path: &str) -> Result<Self, ReadError> {
        let mut ri = File::open(path)?;
        let mut data: Vec<u8> = Vec::new();
        ri.read_to_end(&mut data)?;
        let (_, res) = frame::router_info(&data[..])?;
        Ok(res)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serialize(|input| frame::gen_router_info(input, self))
    }

    pub fn to_file(&self, path: &str) -> io::Result<()> {
        let mut ri = File::create(path)?;
        ri.write(&self.to_bytes()).map(|_| ())
    }

    fn signature_bytes(&self) -> Vec<u8> {
        serialize(|input| frame::gen_router_info_minus_sig(input, self))
    }

    pub fn sign(&mut self, spk: &SigningPrivateKey) {
        let sig_msg = self.signature_bytes();
        self.signature = Some(spk.sign(&sig_msg).unwrap());
    }

    pub fn verify(&self) -> Result<(), crypto::Error> {
        match self.signature.as_ref() {
            Some(s) => {
                let sig_msg = self.signature_bytes();
                self.router_id.signing_key.verify(&sig_msg, s)
            }
            None => Err(crypto::Error::NoSignature),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{RI_SIGTYPE_1, RI_SIGTYPE_2, ROUTER_INFO};

    #[test]
    fn hash_xor() {
        let mut h = Hash::from_bytes(&[0u8; 32]);
        let h0 = Hash::from_bytes(&[0u8; 32]);
        let h1 = Hash::from_bytes(&[1u8; 32]);
        let h2 = Hash::from_bytes(&[2u8; 32]);
        let h3 = Hash::from_bytes(&[3u8; 32]);
        assert_eq!(h, h0);
        h.xor(&h1);
        assert_eq!(h, h1);
        h.xor(&h2);
        assert_eq!(h, h3);
        h.xor(&h1);
        assert_eq!(h, h2);
        h.xor(&h2);
        assert_eq!(h, h0);
    }

    #[test]
    fn i2pstring_to_csv() {
        let s1 = I2PString(String::from("a-b,c/d,1,2"));
        assert_eq!(
            s1.to_csv(),
            vec![
                I2PString(String::from("a-b")),
                I2PString(String::from("c/d")),
                I2PString(String::from("1")),
                I2PString(String::from("2")),
            ]
        );

        let s2 = I2PString(String::from("asdf"));
        assert_eq!(s2.to_csv(), vec![s2]);
    }

    #[test]
    fn router_identity_hash() {
        let ri_hash = Hash([
            0x26, 0x7a, 0x87, 0x78, 0x0d, 0x0c, 0xa0, 0x9a, 0x21, 0xa0, 0x29, 0xb7, 0x4d, 0x7b,
            0xc3, 0x4d, 0x07, 0xc3, 0x53, 0x02, 0x72, 0xc6, 0x30, 0xaa, 0x4c, 0xc1, 0x1d, 0x61,
            0x90, 0xc7, 0xb6, 0xb4,
        ]);
        match frame::router_info(ROUTER_INFO) {
            Ok((_, ri)) => {
                assert_eq!(ri.router_id.hash(), ri_hash);
            }
            _ => panic!("RouterIdentity parsing failed"),
        }
    }

    #[test]
    fn router_address_options() {
        let style = I2PString::new("test");
        let mut ra = RouterAddress::new(&style, "127.0.0.1:0".parse().unwrap());

        let key = I2PString::new("key");
        let value = I2PString::new("value");
        assert!(ra.option(&key).is_none());

        ra.set_option(key.clone(), value.clone());
        assert_eq!(ra.option(&key).unwrap(), &value);
    }

    #[test]
    fn router_info_address() {
        let rsk = RouterSecretKeys::new();
        let mut ri = RouterInfo::new(rsk.rid);
        let style = I2PString::new("test");
        assert!(ri.address(&style, |_| true).is_none());

        ri.set_addresses(vec![
            RouterAddress::new(&I2PString::new("other"), "127.0.0.1:12345".parse().unwrap()),
            RouterAddress {
                cost: 0,
                expiration: I2PDate(0),
                transport_style: style.clone(),
                options: Mapping(HashMap::new()),
            },
            RouterAddress::new(&style, "127.0.0.1:23456".parse().unwrap()),
            RouterAddress::new(&style, "127.0.0.1:34567".parse().unwrap()),
        ]);

        let ra = ri.address(&style, |_| true).unwrap();
        assert_eq!(ra.transport_style, style);
        assert_eq!(ra.addr().unwrap(), "127.0.0.1:23456".parse().unwrap());

        let ra = ri
            .address(&style, |ra| ra.addr().unwrap().port() == 34567)
            .unwrap();
        assert_eq!(ra.transport_style, style);
        assert_eq!(ra.addr().unwrap(), "127.0.0.1:34567".parse().unwrap());
    }

    #[test]
    fn router_info_sign() {
        let rsk = RouterSecretKeys::new();
        let mut ri = RouterInfo::new(rsk.rid);
        assert!(ri.signature.is_none());
        ri.sign(&rsk.signing_private_key);
        assert!(ri.signature.is_some());
        assert!(ri.verify().is_ok());
    }

    fn router_info_verify(data: &[u8]) {
        match frame::router_info(data) {
            Ok((_, ri)) => {
                assert!(ri.verify().is_ok());
            }
            Err(e) => panic!("RouterInfo parsing failed: {}", e),
        }
    }

    #[test]
    fn router_info_verify_sigtype_1() {
        router_info_verify(RI_SIGTYPE_1)
    }

    #[test]
    fn router_info_verify_sigtype_2() {
        router_info_verify(RI_SIGTYPE_2)
    }

    #[test]
    fn router_info_verify_sigtype_7() {
        router_info_verify(ROUTER_INFO)
    }
}
