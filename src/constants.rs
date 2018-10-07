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

/// From https://geti2p.net/spec/cryptography#dsa
pub const I2P_DSA_P: &str = "\
                             9C05B2AA_960D9B97_B8931963_C9CC9E8C_3026E9B8_ED92FAD0\
                             A69CC886_D5BF8015_FCADAE31_A0AD18FA_B3F01B00_A358DE23\
                             7655C496_4AFAA2B3_37E96AD3_16B9FB1C_C564B5AE_C5B69A9F\
                             F6C3E454_8707FEF8_503D91DD_8602E867_E6D35D22_35C1869C\
                             E2479C3B_9D5401DE_04E0727F_B33D6511_285D4CF2_9538D9E3\
                             B6051F5B_22CC1C93";

/// From https://geti2p.net/spec/cryptography#dsa
pub const I2P_DSA_Q: &str = "A5DFC28F_EF4CA1E2_86744CD8_EED9D29D_684046B7";

/// From https://geti2p.net/spec/cryptography#dsa
pub const I2P_DSA_G: &str = "\
                             0C1F4D27_D40093B4_29E962D7_223824E0_BBC47E7C_832A3923\
                             6FC683AF_84889581_075FF908_2ED32353_D4374D73_01CDA1D2\
                             3C431F46_98599DDA_02451824_FF369752_593647CC_3DDC197D\
                             E985E43D_136CDCFC_6BD5409C_D2F45082_1142A5E6_F8EB1C3A\
                             B5D0484B_8129FCF1_7BCE4F7F_33321C3C_B3DBB14A_905E7B2B\
                             3E93BE47_08CBCC82";

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
    pub static ref DSA_P: BigUint = BigUint::from_str_radix(I2P_DSA_P, 16).unwrap();
    pub static ref DSA_Q: BigUint = BigUint::from_str_radix(I2P_DSA_Q, 16).unwrap();
    pub static ref DSA_QM2: BigUint = (&(*DSA_Q)).sub(BigUint::one()).sub(BigUint::one());
    pub static ref DSA_G: BigUint = BigUint::from_str_radix(I2P_DSA_G, 16).unwrap();
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
