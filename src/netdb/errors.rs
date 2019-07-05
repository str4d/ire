//! Network database error handling.

use std::fmt;
use std::time::Duration;

use crate::crypto;

pub enum Error {
    Lookup(LookupError),
    Store(StoreError),
    Closed,
}

impl From<LookupError> for Error {
    fn from(e: LookupError) -> Self {
        Error::Lookup(e)
    }
}

impl From<StoreError> for Error {
    fn from(e: StoreError) -> Self {
        Error::Store(e)
    }
}

#[cfg_attr(tarpaulin, skip)]
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Lookup(e) => write!(f, "Lookup error: {}", e),
            Error::Store(e) => write!(f, "Store error: {}", e),
            Error::Closed => write!(f, "NetDB closed"),
        }
    }
}

/// Network database lookup errors
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LookupError {
    NotFound,
    NoPath,
    SendFailure,
    TimedOut,
    TimerFailure,
}

#[cfg_attr(tarpaulin, skip)]
impl fmt::Display for LookupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LookupError::NotFound => "Key not found".fmt(f),
            LookupError::NoPath => "No path to send lookup".fmt(f),
            LookupError::SendFailure => "Send failure".fmt(f),
            LookupError::TimedOut => "Lookup timed out".fmt(f),
            LookupError::TimerFailure => "Timer failure".fmt(f),
        }
    }
}

/// Network database store errors
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreError {
    Crypto(crypto::Error),
    Expired(Duration),
    InvalidKey,
    PublishedInFuture,
    WrongNetwork,
}

impl From<crypto::Error> for StoreError {
    fn from(e: crypto::Error) -> Self {
        StoreError::Crypto(e)
    }
}

#[cfg_attr(tarpaulin, skip)]
impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Crypto(e) => e.fmt(f),
            StoreError::Expired(age) => {
                format!("Too old (published {} seconds ago)", age.as_secs()).fmt(f)
            }
            StoreError::InvalidKey => "Key does not match RouterInfo's RouterIdentity".fmt(f),
            StoreError::PublishedInFuture => "Published in future".fmt(f),
            StoreError::WrongNetwork => "Not in our network".fmt(f),
        }
    }
}
