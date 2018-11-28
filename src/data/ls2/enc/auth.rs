pub(super) const AUTH_ID_LEN: usize = 8;
pub(super) const AUTH_COOKIE_LEN: usize = 32;

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
