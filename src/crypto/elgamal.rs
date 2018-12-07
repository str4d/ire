//! Implementation of I2P's ElGamal public-key encryption scheme over the
//! 2048-bit MODP DH group.
//!
//! This implementation is not constant-time.
//!
//! Original implementation in Java I2P was based on algorithms 8.17 and 8.18
//! specified in section 8.4.1 of the Handbook of Applied Cryptography.

use num_bigint::{BigUint, RandBigInt};
use num_traits::Zero;
use rand::{rngs::OsRng, Rng};
use sha2::{Digest, Sha256};
use std::ops::{Mul, Rem, Sub};

use super::{math::rectify, Error, PrivateKey, PublicKey};
use crate::constants::{ELGAMAL_G, ELGAMAL_P, ELGAMAL_PM1, ELGAMAL_PM2};

fn gen_gamma_k() -> (BigUint, BigUint) {
    let mut rng = OsRng::new().expect("should be able to construct RNG");

    // Select a random integer k, 1 <= k <= p - 2
    let k = loop {
        let k = rng.gen_biguint(2048);
        if !k.is_zero() && k <= *ELGAMAL_PM2 {
            break k;
        }
    };

    // γ = α^k mod p
    let gamma = ELGAMAL_G.modpow(&k, &ELGAMAL_P);

    (k, gamma)
}

/// Generates ElGamal keypairs.
pub struct KeyPairGenerator;

impl KeyPairGenerator {
    /// ElGamal key generation, following algorithm 8.17.
    pub fn generate() -> (PrivateKey, PublicKey) {
        // Select a random integer a, 1 <= a <= p - 2
        // Public key is α^a mod p
        let (a, alpha_a) = gen_gamma_k();

        let priv_key = {
            let buf = rectify(&a, 256);
            let mut x = [0u8; 256];
            x.copy_from_slice(&buf[..]);
            PrivateKey(x)
        };

        let pub_key = {
            let buf = rectify(&alpha_a, 256);
            let mut x = [0u8; 256];
            x.copy_from_slice(&buf[..]);
            PublicKey(x)
        };

        (priv_key, pub_key)
    }
}

pub struct Encryptor(BigUint);

impl<'a> From<&'a PublicKey> for Encryptor {
    fn from(pub_key: &PublicKey) -> Self {
        Encryptor(BigUint::from_bytes_be(&pub_key.0[..]))
    }
}

impl Encryptor {
    /// Basic ElGamal encryption, following algorithm 8.18 1).
    fn encrypt_basic(&self, msg: &[u8]) -> Result<(BigUint, BigUint), Error> {
        // Represent the message as an integer m in the range {0, 1, ..., p - 1}
        let m = BigUint::from_bytes_be(msg);
        if m > *ELGAMAL_PM1 {
            return Err(Error::InvalidMessage);
        }

        // Select a random integer k, 1 <= k <= p - 2
        // γ = α^k mod p
        let (k, gamma) = gen_gamma_k();

        // δ = m * (α^a)^k mod p
        let s = self.0.modpow(&k, &ELGAMAL_P);
        let delta = m.mul(s).rem(&(*ELGAMAL_P));

        Ok((gamma, delta))
    }

    /// ElGamal encryption using I2P's message and ciphertext encoding schemes.
    pub fn encrypt(&self, msg: &[u8]) -> Result<[u8; 514], Error> {
        // Message must be no more than 222 bytes
        if msg.len() > 222 {
            return Err(Error::InvalidMessage);
        }

        let mut rng = OsRng::new().expect("should be able to construct RNG");
        let hash = Sha256::digest(msg);

        // ElGamal plaintext:
        // 0              1             33
        // | nonzero byte | SHA256(msg) | msg |
        let mut data = Vec::with_capacity(33 + msg.len());
        data.push(loop {
            let val = rng.gen();
            if val != 0 {
                break val;
            }
        });
        data.extend_from_slice(hash.as_slice());
        data.extend_from_slice(msg);

        self.encrypt_basic(&data).map(|(gamma, delta)| {
            // ElGamal ciphertext:
            // 0   1                       257 258                      514
            // | 0 | padding zeroes | gamma | 0 | padding zeroes | delta |
            let gamma = rectify(&gamma, 256);
            let delta = rectify(&delta, 256);
            let mut ct = [0u8; 514];
            ct[1..257].copy_from_slice(&gamma);
            ct[258..514].copy_from_slice(&delta);
            ct
        })
    }
}

pub struct Decryptor(BigUint);

impl<'a> From<&'a PrivateKey> for Decryptor {
    fn from(priv_key: &PrivateKey) -> Self {
        Decryptor(BigUint::from_bytes_be(&priv_key.0[..]))
    }
}

impl Decryptor {
    /// Basic ElGamal decryption, following algorithm 8.18 2).
    fn decrypt_basic(&self, (gamma, delta): (BigUint, BigUint)) -> Vec<u8> {
        // γ^{-a} = γ^{p-1-a}
        let gamma_neg_a = gamma.modpow(&(&(*ELGAMAL_PM1)).sub(&self.0), &ELGAMAL_P);

        // m = (γ^{-a}) * δ mod p
        let m = gamma_neg_a.mul(delta).rem(&(*ELGAMAL_P));

        m.to_bytes_be()
    }

    /// ElGamal decryption using I2P's message and ciphertext encoding schemes.
    // TODO: Errors
    pub fn decrypt(&self, ct: &[u8]) -> Result<Vec<u8>, Error> {
        // Ciphertext must be 514 bytes
        if ct.len() != 514 {
            return Err(Error::InvalidCiphertext);
        }

        // ElGamal ciphertext:
        // 0   1                       257 258                      514
        // | 0 | padding zeroes | gamma | 0 | padding zeroes | delta |
        let gamma = BigUint::from_bytes_be(&ct[..257]);
        let delta = BigUint::from_bytes_be(&ct[257..]);

        let data = self.decrypt_basic((gamma, delta));
        if data.len() < 33 {
            // Decrypted data is too small
            return Err(Error::InvalidCiphertext);
        }

        // ElGamal plaintext:
        // 0              1             33
        // | nonzero byte | SHA256(msg) | msg |
        let msg = data[33..].to_vec();
        let hash = Sha256::digest(&msg);
        if hash.as_slice() == &data[1..33] {
            Ok(msg)
        } else {
            Err(Error::InvalidCiphertext)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Decryptor, Encryptor, KeyPairGenerator};
    use crate::constants::I2P_BASE64;
    use crate::crypto::{PrivateKey, PublicKey};

    #[test]
    fn round_trip_basic() {
        let (priv_key, pub_key) = KeyPairGenerator::generate();
        let enc = Encryptor::from(&pub_key);
        let dec = Decryptor::from(&priv_key);

        // All-zeroes message is returned as a single byte
        let msg = [0u8; 256];
        let ct = enc.encrypt_basic(&msg[..]).unwrap();
        let pt = dec.decrypt_basic(ct);
        assert_eq!(&pt, &[0]);

        // All-ones message is returned as-is
        let msg = [1u8; 256];
        let ct = enc.encrypt_basic(&msg[..]).unwrap();
        let pt = dec.decrypt_basic(ct);
        assert_eq!(&pt[..], &msg[..]);
    }

    #[test]
    fn round_trip() {
        let (priv_key, pub_key) = KeyPairGenerator::generate();
        let enc = Encryptor::from(&pub_key);
        let dec = Decryptor::from(&priv_key);

        // Message too long
        assert!(enc.encrypt(&[0u8; 223]).is_err());

        // Full-width all-zeroes message
        let msg = [0u8; 222];
        let ct = enc.encrypt(&msg[..]).unwrap();
        let pt = dec.decrypt(&ct).unwrap();
        assert_eq!(&pt[..], &msg[..]);

        // Short all-zeroes message
        let msg = [0u8; 8];
        let ct = enc.encrypt(&msg[..]).unwrap();
        let pt = dec.decrypt(&ct).unwrap();
        assert_eq!(&pt[..], &msg[..]);

        // Full-width all-ones message
        let msg = [1u8; 222];
        let ct = enc.encrypt(&msg[..]).unwrap();
        let pt = dec.decrypt(&ct).unwrap();
        assert_eq!(&pt[..], &msg[..]);

        // Short all-ones message
        let msg = [1u8; 8];
        let ct = enc.encrypt(&msg[..]).unwrap();
        let pt = dec.decrypt(&ct).unwrap();
        assert_eq!(&pt[..], &msg[..]);
    }

    /// From `core/java/test/junit/net/i2p/crypto/ElGamalTest.java` in Java I2P.
    #[test]
    fn test_vectors() {
        let pub_key = "pOvBUMrSUUeN5awynzbPbCAwe3MqWprhSpp3OR7pvdfm9PhWaNbPoKRLeEmDoUwyNDoHE0\
                       E6mcZSG8qPQ8XUZFlczpilOl0MJBvsI9u9SMyi~bEqzSgzh9FNfS-NcGji3q2wI~Ux~q5B\
                       KOjGlyMLgd1nxl5R5wIYL4uHKZNaYuArsRYmtV~MgMQPGvDtIbdGTV6aL6UbOYryzQSUMY\
                       OuO3S~YoBjA6Nmi0SeJM3tyTxlI6U1EYjR6oQcI4SOFUW4L~8pfYWijcncCODAqpXVN6ZI\
                       AJ3a6vjxGu56IDp4xCcKlOEHgdXvqmEC67dR5qf2btH6dtWoB3-Z6QPsS6tPTQ==";
        let priv_key = "gMlIhURVXU8uPube20Xr8E1K11g-3qZxOj1riThHqt-rBx72MPq5ivT1rr28cE9mzOmsXi\
                        bbsuBuQKYDvF7hGICRB3ROSPePYhcupV3j7XiXUIYjWNw9hvylHXK~nTT7jkpIBazBJZfr\
                        LJPcDZTDB0YnCOHOL-KFn4N1R5B22g0iYRABN~O10AUjQmf1epklAXPqYlzmOYeJSfTPBI\
                        E44nEccWJp0M0KynhKVbDI0v9VYm6sPFK7WrzRyWwHL~r735wiRkwywuMmKJtA7-PuJjcW\
                        NLkJwx6WScH2msMzhzYPi8JSZJBl~PosX934l-L0T-KNV4jg1Ih6yoCnm1748A==";

        struct TestVector<'a> {
            msg: &'a str,
            ct: &'a str,
        };
        let test_vectors = vec![
            TestVector {
                msg: "",
                ct: "AMfISa8KvTpaC7KXZzSvC2axyiSk0xPexBAf29yU~IKq21DzaU19wQcGJg-ktpG4hjGSg7\
                     u-mJ07b61yo-EGmVGZsv3nYuQYW-GjvsZQa9nm98VljlMtWrxu7TsRXw~SQlWQxMvthqJB\
                     1A7Y7Qa~C7-UlRytkD-cpVdgUfM-esuMWmjGs6Vc33N5U-tce5Fywa-9y7PSn3ukBO8KGR\
                     wm7T12~H2gvhgxrVeK2roOzsV7f5dGkvBQRZJ309Vg3j0kjaxWutgI3vli0pzDbSK9d5NR\
                     -GUDtdOb6IIfLiOckBegcv6I-wlSXjYJe8mIoaK45Ok3rEpHwWKVKS2MeuI7AmsAWgkQmW\
                     f8irmZaKc9X910VWSO5GYu6006hSc~r2TL3O7vwtW-Z9Oq~sAam9av1PPVJzAx8A4g~m~1\
                     avtNnncwlChsGo6mZHXqz-QMdMJXXP57f4bx36ZomkvpM-ZLlFAn-a~42KQJAApo4LfEyk\
                     7DPY2aTXL9ArOCNQIQB4f8QLyjvAvu6M3jzCoGo0wVX6oePfdiokGflriYOcD8rL4NbnCP\
                     ~MSnVzC8LKyRzQVN1tDYj8~njuFqekls6En8KFJ-qgtL4PiYxbnBQDUPoW6y61m-S9r9e9\
                     y8qWd6~YtdAHAxVlw287~HEp9r7kqI-cjdo1337b7~5dm83KK45g5Nfw==",
            },
            TestVector {
                msg: "hello world",
                ct: "AIrd65mG1FJ~9J-DDSyhryVejJBSIjYOqV3GYmHDWgwLchTwq-bJS7dub3ENk9MZ-C6FIN\
                     gjUFRaLBtfwJnySmNf8pIf1srmgdfqGV2h77ufG5Gs0jggKPmPV~7Z1kTcgsqpL8MyrfXr\
                     Gi86X5ey-T0SZSFc0X1EhaE-47WlyWaGf-~xth6VOR~KG7clOxaOBpks-7WKZNQf7mpQRE\
                     4IsPJyj5p1Rf-MeDbVKbK~52IfXSuUZQ8uZr34KMoy4chjn6e-jBhM4XuaQWhsM~a3Q-zE\
                     pV-ea6t0bQTYfsbG9ch7pJuDPHM64o5mF9FS5-JGr7MOtfP7KDNHiYM2~-uC6BIAbiqBN8\
                     WSLX1mrHVuhiM-hiJ7U4oq~HYB6N~U980sCIW0dgFBbhalzzQhJQSrC1DFDqGfL5-L25mj\
                     ArP8dtvN0JY3LSnbcsm-pT9ttFHCPGomLfaAuP7ohknBoXK0j9e6~splg5sUA9TfLeBfqc\
                     Lr0Sf8b3l~PvmrVkbVcaE8yUqSS6JFdt3pavjyyAQSmSlb2jVNKGPlrov5QLzlbH7G~AUv\
                     IehsbGQX5ptRROtSojN~iYx3WQTOa-JLEC-AL7RbRu6B62p9I0pD0JgbUfCc4C4l9E9W~s\
                     MuaJLAXxh0b2miF7C5bzZHxbt~MtZ7Ho5qpZMitXyoE3icb43B6Y1sbA==",
            },
            TestVector {
                msg: "1234567890123456789012345678901234567890123456789012345678901234567890\
                      1234567890123456789012345678901234567890123456789012345678901234567890\
                      1234567890123456789012345678901234567890123456789012345678901234567890\
                      123456789012",
                ct: "ACjb0FkTIQbnEzCZlYXGxekznfJad5uW~F5Mbu~0wtsI1O2veqdr7Mb0N754xdIz7929Ti\
                     1Kz-CxVEAkb3RBbVNcYHLfjy23oQ4BCioDKQaJcdkJqXa~Orm7Ta2tbkhM1Mx05MDrQaVF\
                     gCVXtwTsPSLVK8VwScjPIFLXgQqqZ5osq~WhaMcYe2I2RCQLOx2VzaKbT21MMbtF70a-nK\
                     WovkRUNfJEPeJosFwF2duAD0BHHrPiryK9BPDhyOiyN82ahOi2uim1Nt5yhlP3xo7cLV2p\
                     6kTlR1BNC5pYjtsvetZf6wk-solNUrJWIzcuc18uRDNH5K90GTL6FXPMSulM~E4ATRQfhZ\
                     fkW9xCrBIaIQM49ms2wONsp7fvI07b1r0rt7ZwCFOFit1HSAKl8UpsAYu-EsIO1qAK7vvO\
                     UV~0OuBXkMZEyJT-uIVfbE~xrwPE0zPYE~parSVQgi~yNQBxukUM1smAM5xXVvJu8GjmE-\
                     kJZw1cxaYLGsJjDHDk4HfEsyQVVPZ0V3bQvhB1tg5cCsTH~VNjts4taDTPWfDZmjtVaxxr\
                     PRII4NEDKqEzg3JBevM~yft-RDfMc8RVlm-gCGANrRQORFii7uD3o9~y~4P2tLnO7Fy3m5\
                     rdjRsOsWnCQZzw37mcBoT9rEZPrVpD8pjebJ1~HNc764xIpXDWVt8CbA==",
            },
            TestVector {
                msg: "\0x00",
                ct: "AHDZBKiWeaIYQS9R1l70IlRnoplwKTkLP2dLlXmVh1gB33kx65uX8OMb3hdZEO0Bbzxkkx\
                     quqlNn5w166nJO4nPbpEzVfgtY4ClUuv~W4H4CXBr0FcZM1COAkd6rtp6~lUp7cZ8FAkpH\
                     spl95IxlFM-F1HwiPcbmTjRO1AwCal4sH8S5WmJCvBU6jH6pBPo~9B9vAtP7vX1EwsG2Jf\
                     CQXkVkfvbWpSicbsWn77aECedS3HkIMrXrxojp7gAiPgQhX4NR387rcUPFsMHGeUraTUPZ\
                     D7ctk5tpUuYYwRQc5cRKHa4zOq~AQyljx5w5~FByLda--6yCe7qDcILyTygudJ4AHRs1pJ\
                     RU3uuRTHZx0XJQo~cPsoQ2piAOohITX9~yMCimCgv2EIhY3Z-mAgo8qQ4iMbItoE1cl93I\
                     u2YV2n4wMq9laBx0shuKOJqO3rjRnszzCbqMuFAXfc3KgGDEaCpI7049s3i2yIcv4vT9uU\
                     AlrM-dsrdw0JgJiFYl0JXh~TO0IyrcVcLpgZYgRhEvTAdkDNwTs-2GK4tzdPEd34os4a2c\
                     DPL8joh3jhp~eGoRzrpcdRekxENdzheL4w3wD1fJ9W2-leil1FH6EPc3FSL6e~nqbw69gN\
                     bsuXAMQ6CobukJdJEy37uKmEw4v6WPyfYMUUacchv1JoNfkHLpnAWifQ==",
            },
            TestVector {
                msg: "\0x00\0x00\0x00",
                ct: "AGwvKAMJcPAliP-n7F0Rrj0JMRaFGjww~zvBjyzc~SPJrBF831cMqZFRmMHotgA7S5BrH2\
                     6CL8okI2N-7as0F2l7OPx50dFEwSVSjqBjVV6SGRFC8oS-ii1FURMz2SCHSaj6kazAYq4s\
                     DwyqR7vnUrOtPnZujHSU~a02jinyn-QOaHkxRiUp-Oo0jlZiU5xomXgLdkhtuz6725WUDj\
                     3uVlMtIYfeKQsTdasujHe1oQhUmp58jfg5vgZ8g87cY8rn4p9DRwDBBuo6vi5on7T13sGx\
                     tY9wz6HTpwzDhEqpNrj~h4JibElfi0Jo8ZllmNTO1ZCNpUQgASoTtyFLD5rk6cIAMK0R7A\
                     7hjB0aelKM-V7AHkj-Fhrcm8xIgWhKaLn2wKbVNpAkllkiLALyfWJ9dhJ804RWQTMPE-GD\
                     kBMIFOOJ9MhpEN533OBQDwUKcoxMjl0zOMNCLx8IdCE6cLtUDKJXLB0atnDpLkBer6FwXP\
                     81EvKDYhtp1GsbiKvZDt8LSPJQnm2EdA3Pr9fpAisJ5Ocaxlfa6~uQCuqGA9nJ9n6w03u-\
                     ZpSMhSh4zm2s1MqijmaJRc-QNKmN~u1hh3R2hwWNi7FoStMA87sutEBXMdFI8un7StHNSE\
                     iCYwmmW2Nu3djkM-X8gGjSsdrphTU7uOXbwazmguobFGxI0JujYruM5Q==",
            },
            TestVector {
                msg: "\0x00\0x01\0x02\0x00",
                ct: "ALFYtPSwEEW3eTO4hLw6PZNlBKoSIseQNBi034gq6FwYEZsJOAo-1VXcvMviKw2MCP9ZkH\
                     lTNBfzc79ms2TU8kXxc7zwUc-l2HJLWh6dj2tIQLR8bbWM7U0iUx4XB1B-FEvdhbjz7dsu\
                     6SBXVhxo2ulrk7Q7vX3kPrePhZZldcNZcS0t65DHYYwL~E~ROjQwOO4Cb~8FgiIUjb8CCN\
                     w5zxJpBaEt7UvZffkVwj-EWTzFy3DIjWIRizxnsI~mUI-VspPE~xlmFX~TwPS9UbwJDpm8\
                     -WzINFcehSzF3y9rzSMX-KbU8m4YZj07itZOiIbWgLeulTUB-UgwEkfJBG0xiSUAspZf2~\
                     t~NthBlpcdrBLADXTJ7Jmkk4MIfysV~JpDB7IVg0v4WcUUwF3sYMmBCdPCwyYf0hTrl2Yb\
                     L6kmm4u97WgQqf0TyzXtVZYwjct4LzZlyH591y6O6AQ4Fydqos9ABInzu-SbXq6S1Hi6vr\
                     aNWU3mcy2myie32EEXtkX7P8eXWY35GCv9ThPEYHG5g1qKOk95ZCTYYwlpgeyaMKsnN3C~\
                     x9TJA8K8T44v7vE6--Nw4Z4zjepwkIOht9iQsA6D6wRUQpeYX8bjIyYDPC7GUHq0WhXR6E\
                     6Ojc9k8V5uh0SZ-rCQX6sccdk3JbyRhjGP4rSKr6MmvxVVsqBjcbpxsg==",
            },
        ];

        let enc = {
            let mut data = [0u8; 256];
            data.copy_from_slice(&I2P_BASE64.decode(pub_key.as_bytes()).unwrap());
            Encryptor::from(&PublicKey(data))
        };
        let dec = {
            let mut data = [0u8; 256];
            data.copy_from_slice(&I2P_BASE64.decode(priv_key.as_bytes()).unwrap());
            Decryptor::from(&PrivateKey(data))
        };

        for tv in test_vectors {
            let msg = tv.msg.as_bytes();
            let ct = I2P_BASE64.decode(tv.ct.as_bytes()).unwrap();

            // Check round-trip
            assert_eq!(dec.decrypt(&enc.encrypt(msg).unwrap()).unwrap(), msg);

            // Check test vector
            assert_eq!(dec.decrypt(&ct).unwrap(), msg);
        }
    }
}
