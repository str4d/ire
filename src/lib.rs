#![cfg_attr(all(test, feature = "nightly"), feature(test))]

//! An I2P router implementation in Rust.

#[macro_use]
extern crate arrayref;
#[macro_use]
extern crate futures;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
#[macro_use]
extern crate nom;

extern crate aesti;
extern crate byteorder;
extern crate bytes;
extern crate cookie_factory;
extern crate data_encoding;
extern crate ed25519_dalek;
extern crate flate2;
extern crate i2p_snow;
extern crate itertools;
extern crate num;
extern crate rand;
extern crate sha2;
extern crate siphasher;
extern crate tokio;
extern crate tokio_codec;
extern crate tokio_io;
extern crate tokio_timer;

#[cfg(test)]
#[macro_use]
extern crate pretty_assertions;
#[cfg(test)]
extern crate tempfile;
#[cfg(all(test, feature = "nightly"))]
extern crate test;

mod constants;
pub mod crypto;
pub mod data;
pub mod i2np;
pub mod transport;
