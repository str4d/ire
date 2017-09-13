extern crate aesti;
#[macro_use]
extern crate arrayref;
extern crate cookie_factory;
extern crate ed25519_dalek;
extern crate itertools;
#[macro_use]
extern crate nom;
extern crate num;
extern crate rand;
extern crate sha2;

#[cfg(test)]
#[macro_use]
extern crate pretty_assertions;

mod constants;
mod crypto;
mod data;

fn main() {
    println!("Hello, world!");
}
