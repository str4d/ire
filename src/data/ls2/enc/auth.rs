use rand::{rngs::OsRng, RngCore};
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

use super::{kdf, stream_cipher, Error, S_IV_LEN, S_KEY_LEN};

pub(super) const AUTH_ID_LEN: usize = 8;
pub(super) const AUTH_COOKIE_LEN: usize = 32;

const X25519_AUTH_INFO: &[u8; 8] = b"ELS2_XCA";

#[derive(Clone)]
pub struct X25519ClientInfo(pub [u8; 32]);

/// Client information
#[derive(Clone)]
pub enum ClientInfo {
    X25519(Vec<X25519ClientInfo>),
}

// Client's secret authentication key
pub enum ClientSecretKey {
    X25519([u8; 32]),
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
}

impl ClientAuthType {
    pub(super) fn from_info(
        client_info: Option<ClientInfo>,
        subcredential: &[u8],
        created: u32,
    ) -> (Vec<u8>, Option<Self>) {
        let mut rng = OsRng::new().unwrap();

        match client_info {
            Some(ClientInfo::X25519(clients)) => {
                let mut auth_cookie = vec![];
                auth_cookie.resize(AUTH_COOKIE_LEN, 0);
                rng.fill_bytes(&mut auth_cookie[..]);

                let mut esk = [0u8; 32];
                rng.fill_bytes(&mut esk[..]);
                let epk = x25519(esk, X25519_BASEPOINT_BYTES);

                let auth_data = clients
                    .into_iter()
                    .map(|client| {
                        let shared_secret = x25519(esk, client.0);

                        let mut okm = [0; S_KEY_LEN + S_IV_LEN + AUTH_ID_LEN];
                        kdf(
                            &shared_secret,
                            subcredential,
                            created,
                            &epk,
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

                (auth_cookie, Some(ClientAuthType::X25519(epk, auth_data)))
            }
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
        match (self, key) {
            (ClientAuthType::X25519(epk, auth_data), ClientSecretKey::X25519(sk)) => {
                let shared_secret = x25519(*sk, *epk);

                let mut okm = [0; S_KEY_LEN + S_IV_LEN + AUTH_ID_LEN];
                kdf(
                    &shared_secret,
                    subcredential,
                    created,
                    &epk[..],
                    X25519_AUTH_INFO,
                    &mut okm,
                );
                let client_key = &okm[0..S_KEY_LEN];
                let client_iv = &okm[S_KEY_LEN..S_KEY_LEN + S_IV_LEN];
                let client_id = &okm[S_KEY_LEN + S_IV_LEN..S_KEY_LEN + S_IV_LEN + AUTH_ID_LEN];

                // Scan the list of clients to find ourselves
                match auth_data
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
            }
        }
    }
}
