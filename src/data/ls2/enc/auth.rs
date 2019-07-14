use rand::{rngs::OsRng, RngCore};
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

use super::{kdf, stream_cipher, Error, S_IV_LEN, S_KEY_LEN};

pub(super) const AUTH_ID_LEN: usize = 8;
pub(super) const AUTH_COOKIE_LEN: usize = 32;

const X25519_AUTH_INFO: &[u8; 8] = b"ELS2_XCA";

#[derive(Clone)]
pub struct X25519ClientInfo(pub [u8; 32]);

#[derive(Clone)]
pub struct PSKClientInfo(pub [u8; 32]);

/// Client information
#[derive(Clone)]
pub enum ClientInfo {
    X25519(Vec<X25519ClientInfo>),
    PSK(Vec<PSKClientInfo>),
}

// Client's secret authentication key
pub enum ClientSecretKey {
    X25519([u8; 32]),
    PSK([u8; 32]),
}

/// Per-client authentication data.
#[derive(Debug, PartialEq)]
pub(super) struct ClientAuthData {
    pub(super) client_id: [u8; AUTH_ID_LEN],
    pub(super) client_cookie: [u8; AUTH_COOKIE_LEN],
}

/// Supported types of client authentication.
#[derive(Debug, PartialEq)]
pub(super) enum ClientAuthType {
    X25519([u8; 32], Vec<ClientAuthData>),
    PSK([u8; 32], Vec<ClientAuthData>),
}

impl ClientAuthType {
    pub(super) fn from_info(
        client_info: Option<ClientInfo>,
        subcredential: &[u8],
        created: u32,
    ) -> (Vec<u8>, Option<Self>) {
        let mut rng = OsRng::new().unwrap();

        macro_rules! base_auth {
            ($clients:ident, $gen_auth_seed:expr, $gen_secret_value:expr, $salt:expr, $auth_type:ident) => {{
                let mut auth_cookie = vec![];
                auth_cookie.resize(AUTH_COOKIE_LEN, 0);
                rng.fill_bytes(&mut auth_cookie[..]);

                let auth_seed = $gen_auth_seed;

                let auth_data = $clients
                    .into_iter()
                    .map(|client| {
                        let mut okm = [0; S_KEY_LEN + S_IV_LEN + AUTH_ID_LEN];
                        kdf(
                            &$gen_secret_value(auth_seed, client.0),
                            subcredential,
                            created,
                            &$salt(auth_seed),
                            X25519_AUTH_INFO,
                            &mut okm,
                        );

                        let client_key = &okm[0..S_KEY_LEN];
                        let client_iv = &okm[S_KEY_LEN..S_KEY_LEN + S_IV_LEN];

                        let mut client_id = [0; AUTH_ID_LEN];
                        client_id.copy_from_slice(
                            &okm[S_KEY_LEN + S_IV_LEN..S_KEY_LEN + S_IV_LEN + AUTH_ID_LEN],
                        );

                        let mut client_cookie = [0; AUTH_COOKIE_LEN];
                        stream_cipher(client_key, client_iv, &auth_cookie, &mut client_cookie);

                        ClientAuthData {
                            client_id,
                            client_cookie,
                        }
                    })
                    .collect();

                (
                    auth_cookie,
                    Some(ClientAuthType::$auth_type($salt(auth_seed), auth_data)),
                )
            }};
        }

        match client_info {
            Some(ClientInfo::X25519(clients)) => base_auth!(
                clients,
                {
                    let mut esk = [0u8; 32];
                    rng.fill_bytes(&mut esk[..]);
                    let epk = x25519(esk, X25519_BASEPOINT_BYTES);
                    (esk, epk)
                },
                |(esk, _), client_info| x25519(esk, client_info),
                |(_, epk)| epk,
                X25519
            ),
            Some(ClientInfo::PSK(clients)) => base_auth!(
                clients,
                {
                    let mut auth_salt = [0; 32];
                    rng.fill_bytes(&mut auth_salt[..]);
                    auth_salt
                },
                |_, client_info| client_info,
                |auth_salt| auth_salt,
                PSK
            ),
            None => (vec![], None),
        }
    }

    /// Returns the authCookie if the client is authorized, or an error otherwise.
    pub(super) fn authenticate(
        &self,
        key: &ClientSecretKey,
        subcredential: &[u8],
        created: u32,
    ) -> Result<Vec<u8>, Error> {
        macro_rules! base_auth {
            ($secret_value:expr, $salt:expr, $auth_data:ident) => {{
                let mut okm = [0; S_KEY_LEN + S_IV_LEN + AUTH_ID_LEN];
                kdf(
                    $secret_value,
                    subcredential,
                    created,
                    $salt,
                    X25519_AUTH_INFO,
                    &mut okm,
                );
                let client_key = &okm[0..S_KEY_LEN];
                let client_iv = &okm[S_KEY_LEN..S_KEY_LEN + S_IV_LEN];
                let client_id = &okm[S_KEY_LEN + S_IV_LEN..S_KEY_LEN + S_IV_LEN + AUTH_ID_LEN];

                // Scan the list of clients to find ourselves
                match $auth_data
                    .iter()
                    .filter_map(|data| {
                        if data.client_id == client_id {
                            // We are on the list! Get dat cookie :)
                            let mut auth_cookie = vec![];
                            auth_cookie.resize(AUTH_COOKIE_LEN, 0);
                            stream_cipher(
                                client_key,
                                client_iv,
                                &data.client_cookie,
                                &mut auth_cookie,
                            );
                            Some(auth_cookie)
                        } else {
                            None
                        }
                    })
                    .next()
                {
                    Some(auth_cookie) => Ok(auth_cookie),
                    None => Err(Error::NotAuthorised),
                }
            }};
        }

        match (self, key) {
            (ClientAuthType::X25519(epk, auth_data), ClientSecretKey::X25519(sk)) => {
                let shared_secret = x25519(*sk, *epk);
                base_auth!(&shared_secret, &epk[..], auth_data)
            }
            (ClientAuthType::PSK(auth_salt, auth_data), ClientSecretKey::PSK(sk)) => {
                base_auth!(&sk[..], &auth_salt[..], auth_data)
            }
            _ => Err(Error::NotAuthorised),
        }
    }
}
