use data_encoding::{Encoding, Specification};
use num_bigint::BigUint;
use num_traits::{Num, One};
use std::ops::Sub;

lazy_static! {
    pub static ref I2P_BASE64: Encoding = {
        let mut spec = Specification::new();
        spec.symbols
            .push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~");
        spec.padding = Some('=');
        spec.encoding().unwrap()
    };
}

// Sig types
pub const DSA_SHA1: u16 = 0;
pub const ECDSA_SHA256_P256: u16 = 1;
pub const ECDSA_SHA384_P384: u16 = 2;
pub const ECDSA_SHA512_P521: u16 = 3;
pub const ED25519: u16 = 7;

// Enc types
pub const ELGAMAL2048: u16 = 0;

// Key material constants
pub const KEYCERT_SIGKEY_BYTES: usize = 128;

// Crypto constants

/// This modulus is the prime from the 2048-bit MODP DH group:
/// https://tools.ietf.org/html/rfc3526#section-3
pub const RFC3526_2048BIT_MODP_GROUP: &str =
    "FFFFFFFF_FFFFFFFF_C90FDAA2_2168C234_C4C6628B_80DC1CD1\
     29024E08_8A67CC74_020BBEA6_3B139B22_514A0879_8E3404DD\
     EF9519B3_CD3A431B_302B0A6D_F25F1437_4FE1356D_6D51C245\
     E485B576_625E7EC6_F44C42E9_A637ED6B_0BFF5CB6_F406B7ED\
     EE386BFB_5A899FA5_AE9F2411_7C4B1FE6_49286651_ECE45B3D\
     C2007CB8_A163BF05_98DA4836_1C55D39A_69163FA8_FD24CF5F\
     83655D23_DCA3AD96_1C62F356_208552BB_9ED52907_7096966D\
     670C354E_4ABC9804_F1746C08_CA18217C_32905E46_2E36CE3B\
     E39E772C_180E8603_9B2783A2_EC07A28F_B5C55DF0_6F4C52C9\
     DE2BCBF6_95581718_3995497C_EA956AE5_15D22618_98FA0510\
     15728E5A_8AACAA68_FFFFFFFF_FFFFFFFF";

lazy_static! {
    pub static ref ELGAMAL_G: BigUint = BigUint::parse_bytes(b"2", 10).unwrap();
    pub static ref ELGAMAL_P: BigUint =
        BigUint::from_str_radix(RFC3526_2048BIT_MODP_GROUP, 16).unwrap();
    pub static ref ELGAMAL_PM1: BigUint = (&(*ELGAMAL_P)).sub(BigUint::one());
    pub static ref ELGAMAL_PM2: BigUint = (&(*ELGAMAL_PM1)).sub(BigUint::one());
}

// Certificate types
pub const NULL_CERT: u8 = 0;
pub const HASH_CERT: u8 = 1;
pub const HIDDEN_CERT: u8 = 2;
pub const SIGNED_CERT: u8 = 3;
pub const MULTI_CERT: u8 = 4;
pub const KEY_CERT: u8 = 5;
