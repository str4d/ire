extern crate aesti;
#[macro_use]
extern crate arrayref;
extern crate bytes;
extern crate cookie_factory;
extern crate ed25519_dalek;
extern crate flate2;
#[macro_use]
extern crate futures;
extern crate itertools;
#[macro_use]
extern crate nom;
extern crate num;
extern crate rand;
extern crate sha2;
extern crate tokio_core;
extern crate tokio_io;

#[cfg(test)]
#[macro_use]
extern crate pretty_assertions;

mod constants;
mod crypto;
mod data;
mod i2np;
mod transport;

fn main() {
    println!("Hello, world!");
}
