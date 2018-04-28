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
  - [ ] ElGamal
  - [ ] DSA
  - [ ] ECDSA
  - [x] Ed25519
  - [x] AES256
- I2NP
  - [x] Message parsing
  - [ ] Message handling
- Transports
  - [ ] Transport manager
  - [ ] NTCP
    - [x] Handshake
    - [ ] Connection tracking
  - [ ] SSU

## Usage

The binary implements a basic client and server that can be used to test the NTCP
handshake:

1. Generate keys for the server and client:

  ```bash
$ cargo run --release cli gen server.router.keys.dat
$ cargo run --release cli gen client.router.keys.dat
  ```

2. Run the server:

  ```bash
$ RUST_LOG=ire=debug cargo run --release cli server server.router.keys.dat server.router.info 127.0.0.1:12345 127.0.0.1:12346
  ```

3. Run a client:

  ```bash
$ RUST_LOG=ire=debug cargo run --release cli client client.router.keys.dat server.router.info [NTCP|NTCP2]
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
