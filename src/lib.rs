//! An I2P router implementation in Rust.

#![allow(unknown_lints)]
#![cfg_attr(all(test, feature = "nightly"), feature(test))]
// Catch documentation errors caused by code changes.
#![deny(intra_doc_link_resolution_failure)]

#[macro_use]
extern crate arrayref;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;

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
pub mod tunnel;
mod util;

#[cfg(test)]
mod tests;
