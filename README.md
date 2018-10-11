# Ire: the I2P Rust engine

[![Crates.io](https://img.shields.io/crates/v/ire.svg)](https://crates.io/crates/ire)
[![Build Status](https://travis-ci.org/str4d/ire.svg?branch=master)](https://travis-ci.org/str4d/ire)
[![codecov](https://codecov.io/gh/str4d/ire/branch/master/graph/badge.svg)](https://codecov.io/gh/str4d/ire)

Ire is a Rust implementation of an I2P router, designed to participate in the
global, decentralised [I2P network].

[I2P network]: https://geti2p.net

## Development Status

Ire is in pre-alpha; much of the internal architecture still needs to be defined
and implemented.

### Implemented Features

- Cryptographic primitives
  - Signing
    - [ ] ECDSA_SHA256_P256
    - [ ] ECDSA_SHA384_P384
    - [ ] ECDSA_SHA512_P521
    - [x] Ed25519
  - Verifying
    - [x] DSA
    - [x] ECDSA_SHA256_P256
    - [x] ECDSA_SHA384_P384
    - [ ] ECDSA_SHA512_P521
    - [x] RSA_SHA256_2048
    - [x] RSA_SHA384_3072
    - [x] RSA_SHA512_4096
    - [x] Ed25519
  - [x] ElGamal
  - [x] AES256
- I2NP
  - [x] Message parsing
  - [ ] Message handling
- NetDB
  - [x] Local storage
  - [ ] Persistence to disk
  - [x] Reseeding
  - [ ] Lookups
  - [ ] Publishing
  - [ ] Floodfill
- Transports
  - [x] Transport manager
  - [ ] NTCP
    - [x] Handshake
    - [x] Session tracking
    - [ ] Automatic session creation
  - [ ] NTCP2
    - [x] Handshake
    - [x] Session tracking
    - [ ] Automatic session creation
  - [ ] SSU

## Usage

The binary implements a router, along with a basic client that can be used to
test the various transports:

1. Generate keys for the router and client:

  ```bash
$ cargo run --features cli --release cli gen router.keys.dat
$ cargo run --features cli --release cli gen client.router.keys.dat
  ```

2. Run the router:

  ```bash
$ RUST_LOG=ire=debug cargo run --features cli --release cli router router.keys.dat router.info 127.0.0.1:12345 127.0.0.1:12346 ntcp2.keys.dat
  ```

3. Run a client:

  ```bash
$ RUST_LOG=ire=debug cargo run --features cli --release cli client client.router.keys.dat router.info [NTCP|NTCP2]
  ```

## Code of Conduct

We abide by the [Contributor Covenant][cc] and ask that you do as well.

For more information, please see [CODE_OF_CONDUCT.md].

[cc]: https://contributor-covenant.org
[CODE_OF_CONDUCT.md]: https://github.com/str4d/ire/blob/master/CODE_OF_CONDUCT.md

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/str4d/ire

## Copyright

Copyright (c) 2017 [The Ire Developers][AUTHORS].
See [LICENSE.txt] for further details.

[AUTHORS]: https://github.com/str4d/ire/blob/master/AUTHORS.md
[LICENSE.txt]: https://github.com/str4d/ire/blob/master/LICENSE.txt
