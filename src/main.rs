extern crate aesti;
#[macro_use]
extern crate arrayref;
extern crate bytes;
extern crate clap;
extern crate cookie_factory;
extern crate ed25519_dalek;
extern crate env_logger;
extern crate flate2;
#[macro_use]
extern crate futures;
extern crate itertools;
#[macro_use]
extern crate log;
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

use clap::{App, Arg, ArgMatches, SubCommand};
use futures::{Future, Sink};
use tokio_core::reactor::Core;

mod constants;
mod crypto;
mod data;
mod i2np;
mod transport;

fn main() {
    env_logger::init();
    let exit_code = inner_main();
    std::process::exit(exit_code);
}

fn inner_main() -> i32 {
    let matches = App::new("ire")
        .version("0.0.1")
        .author("Jack Grigg <str4d@i2pmail.org>")
        .about("The I2P Rust engine")
        .subcommand(
            SubCommand::with_name("cli")
                .subcommand(
                    SubCommand::with_name("gen")
                        .arg(
                            Arg::with_name("routerKeys")
                                .help("Path to write the router.keys.dat to"),
                        )
                        .arg(Arg::with_name("routerId").help("Path to write the router.info to")),
                )
                .subcommand(
                    SubCommand::with_name("server")
                        .arg(
                            Arg::with_name("routerKeys")
                                .help("Path to the server's router.keys.dat"),
                        )
                        .arg(Arg::with_name("bind").help("Address:Port to bind to")),
                )
                .subcommand(
                    SubCommand::with_name("client")
                        .arg(
                            Arg::with_name("routerKeys")
                                .help("Path to the client's router.keys.dat"),
                        )
                        .arg(Arg::with_name("peerId").help("Path to the peer's router.info file"))
                        .arg(Arg::with_name("addr").help("Address:Port of the peer")),
                ),
        )
        .get_matches();

    match matches.subcommand() {
        ("cli", Some(matches)) => match matches.subcommand() {
            ("gen", Some(matches)) => cli_gen(matches),
            ("server", Some(matches)) => cli_server(matches),
            ("client", Some(matches)) => cli_client(matches),
            (&_, _) => panic!("Invalid matches for cli subcommand"),
        },
        _ => 1,
    }
}

fn cli_gen(args: &ArgMatches) -> i32 {
    let pkf = data::RouterSecretKeys::new();
    pkf.rid.to_file(args.value_of("routerId").unwrap());
    pkf.to_file(args.value_of("routerKeys").unwrap());
    0
}

fn cli_server(args: &ArgMatches) -> i32 {
    let rsk = data::RouterSecretKeys::from_file(args.value_of("routerKeys").unwrap());
    let addr = args.value_of("bind").unwrap().parse().unwrap();

    // Accept all incoming sockets
    info!("Listening on {}", addr);
    let ntcp = transport::ntcp::Engine::new();
    ntcp.listen(rsk.rid, rsk.signing_private_key, &addr);
    0
}

fn cli_client(args: &ArgMatches) -> i32 {
    let mut core = Core::new().unwrap();
    let handle = core.handle();

    let rsk = data::RouterSecretKeys::from_file(args.value_of("routerKeys").unwrap());
    let peer_rid = data::RouterIdentity::from_file(args.value_of("peerId").unwrap());
    let addr = args.value_of("addr").unwrap().parse().unwrap();

    info!("Connecting to {}", addr);
    let ntcp = transport::ntcp::Engine::new();
    let conn = ntcp.connect(rsk.rid, rsk.signing_private_key, peer_rid, &addr, &handle);

    match core.run(conn) {
        Ok(t) => {
            info!("Connection established!");
            let f = t.send(transport::ntcp::Frame::TimeSync(42));
            let f = f.and_then(|t| {
                t.send(transport::ntcp::Frame::Standard(
                    i2np::Message::dummy_data(),
                ))
            });
            match core.run(f) {
                Ok(_) => {
                    info!("Dummy data sent!");
                    0
                }
                Err(e) => {
                    error!("Failed to send dummy data: {:?}", e);
                    1
                }
            }
        }
        Err(e) => {
            error!("Handshake failed: {}", e);
            1
        }
    }
}
