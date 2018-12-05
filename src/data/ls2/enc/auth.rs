use super::Error;

pub(super) const AUTH_ID_LEN: usize = 8;
pub(super) const AUTH_COOKIE_LEN: usize = 32;

pub struct X25519ClientInfo;

/// Client information
pub enum ClientInfo {
    X25519(Vec<X25519ClientInfo>),
}

// Client's secret authentication key
pub enum ClientSecretKey {
    X25519,
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
        _subcredential: &[u8],
        _created: u32,
    ) -> (Vec<u8>, Option<Self>) {
        match client_info {
            Some(ClientInfo::X25519(_clients)) => unimplemented!(),
            None => (vec![], None),
        }
    }

    /// Returns the authCookie if the client is authorized, or an error otherwise.
    pub(super) fn authenticate(
        &self,
        _key: &ClientSecretKey,
        _subcredential: &[u8],
        _created: u32,
    ) -> Result<Vec<u8>, Error> {
        Err(Error::NotAuthorised)
    }
}
