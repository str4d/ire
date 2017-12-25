extern crate actix;
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

use actix::prelude::*;
use clap::{App, Arg, ArgMatches, SubCommand};
use futures::Stream;
use tokio_core::net::TcpListener;

mod constants;
mod crypto;
mod data;
mod i2np;
mod transport;

fn main() {
    env_logger::init().unwrap();
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
    let sys = actix::System::new("ire");

    let rsk = data::RouterSecretKeys::from_file(args.value_of("routerKeys").unwrap());
    let addr = args.value_of("bind").unwrap().parse().unwrap();

    // Accept all incoming sockets
    info!("Listening on {}", addr);
    let listener = TcpListener::bind(&addr, Arbiter::handle()).unwrap();
    let _: () = transport::ntcp::Engine::create(move |ctx| {
        ctx.add_stream(
            listener
                .incoming()
                .map(|(st, addr)| transport::TcpConnect(st, addr)),
        );
        transport::ntcp::Engine::new(rsk.rid, rsk.signing_private_key)
    });

    sys.run()
}

fn cli_client(args: &ArgMatches) -> i32 {
    let sys = actix::System::new("ire-client");

    let rsk = data::RouterSecretKeys::from_file(args.value_of("routerKeys").unwrap());
    let peer_rid = data::RouterIdentity::from_file(args.value_of("peerId").unwrap());
    let addr = args.value_of("addr").unwrap().parse().unwrap();

    info!("Connecting to {}", addr);
    let ntcp = transport::ntcp::Engine::new(rsk.rid, rsk.signing_private_key);
    ntcp.connect(peer_rid, &addr);

    sys.run()
}
