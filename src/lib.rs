#![allow(unknown_lints)]
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

extern crate aes;
extern crate block_modes;
extern crate byteorder;
extern crate bytes;
extern crate chrono;
extern crate config;
extern crate cookie_factory;
extern crate data_encoding;
extern crate flate2;
extern crate i2p_ring;
extern crate i2p_snow;
extern crate itertools;
extern crate native_tls;
extern crate num_bigint;
extern crate num_traits;
extern crate rand;
extern crate ring;
extern crate sha1;
extern crate sha2;
extern crate signatory;
extern crate signatory_dalek;
extern crate signatory_ring;
extern crate siphasher;
extern crate tokio_codec;
extern crate tokio_executor;
extern crate tokio_io;
extern crate tokio_tcp;
extern crate tokio_timer;
extern crate tokio_tls;
extern crate untrusted;
extern crate zip;

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
mod file;
pub mod i2np;
pub mod netdb;
pub mod router;
pub mod transport;

#[cfg(test)]
mod tests;
