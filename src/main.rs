extern crate aesti;
#[macro_use]
extern crate arrayref;
extern crate bytes;
extern crate clap;
extern crate cookie_factory;
extern crate data_encoding;
extern crate ed25519_dalek;
extern crate env_logger;
extern crate flate2;
#[macro_use]
extern crate futures;
extern crate itertools;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
#[macro_use]
extern crate nom;
extern crate num;
extern crate rand;
extern crate sha2;
extern crate snow;
extern crate tokio;
extern crate tokio_codec;
extern crate tokio_io;
extern crate tokio_timer;

#[cfg(test)]
#[macro_use]
extern crate pretty_assertions;

use clap::{App, Arg, ArgMatches, SubCommand};
use futures::{Future, Sink};

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
                    SubCommand::with_name("gen").arg(
                        Arg::with_name("routerKeys")
                            .help("Path to write the router.keys.dat to")
                            .required(true),
                    ),
                )
                .subcommand(
                    SubCommand::with_name("server")
                        .arg(
                            Arg::with_name("routerKeys")
                                .help("Path to the server's router.keys.dat")
                                .required(true),
                        )
                        .arg(
                            Arg::with_name("routerInfo")
                                .help("Path to write the router.info to")
                                .required(true),
                        )
                        .arg(
                            Arg::with_name("ntcp")
                                .help("Address:Port to bind NTCP to")
                                .required(true),
                        )
                        .arg(
                            Arg::with_name("ntcp2")
                                .help("Address:Port to bind NTCP2 to")
                                .required(true),
                        ),
                )
                .subcommand(
                    SubCommand::with_name("client")
                        .arg(
                            Arg::with_name("routerKeys")
                                .help("Path to the client's router.keys.dat")
                                .required(true),
                        )
                        .arg(
                            Arg::with_name("peerInfo")
                                .help("Path to the peer's router.info file")
                                .required(true),
                        )
                        .arg(
                            Arg::with_name("transport")
                                .help("Transport to test")
                                .possible_values(&["NTCP", "NTCP2"])
                                .required(true),
                        ),
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
    pkf.to_file(args.value_of("routerKeys").unwrap()).unwrap();
    0
}

fn cli_server(args: &ArgMatches) -> i32 {
    let rsk = data::RouterSecretKeys::from_file(args.value_of("routerKeys").unwrap()).unwrap();
    let ntcp_addr = args.value_of("ntcp").unwrap().parse().unwrap();
    let ntcp2_addr = args.value_of("ntcp2").unwrap().parse().unwrap();
    let ra = data::RouterAddress::new(&transport::ntcp::NTCP_STYLE, ntcp_addr);
    let ra2 = data::RouterAddress::new(&transport::ntcp2::NTCP2_STYLE, ntcp2_addr);

    let mut ri = data::RouterInfo::new(rsk.rid.clone());
    ri.set_addresses(vec![ra, ra2]);
    ri.sign(&rsk.signing_private_key);
    ri.to_file(args.value_of("routerInfo").unwrap()).unwrap();

    // Accept all incoming sockets
    info!("NTCP:  Listening on {}", ntcp_addr);
    let ntcp = transport::ntcp::Engine::new();
    let listener = ntcp
        .listen(rsk.rid.clone(), rsk.signing_private_key.clone(), &ntcp_addr)
        .map_err(|e| error!("NTCP listener error: {}", e));

    info!("NTCP2: Listening on {}", ntcp2_addr);
    let ntcp2 = transport::ntcp2::Engine::new();
    let listener2 = ntcp2
        .listen(&ntcp2_addr)
        .map_err(|e| error!("NTCP2 listener error: {}", e));

    tokio::run(listener.join(listener2).map(|_| ()));
    0
}

fn cli_client(args: &ArgMatches) -> i32 {
    let rsk = data::RouterSecretKeys::from_file(args.value_of("routerKeys").unwrap()).unwrap();
    let peer_ri = data::RouterInfo::from_file(args.value_of("peerInfo").unwrap()).unwrap();

    info!("Connecting to {}", peer_ri.router_id.hash());
    match args.value_of("transport") {
        Some("NTCP") => {
            let ntcp = transport::ntcp::Engine::new();
            let conn = ntcp
                .connect(rsk.rid, rsk.signing_private_key, peer_ri)
                .and_then(move |t| {
                    info!("Connection established!");
                    t.send(transport::ntcp::Frame::TimeSync(42))
                })
                .and_then(|t| t.send(transport::ntcp::Frame::Standard(i2np::Message::dummy_data())))
                .and_then(|_| {
                    info!("Dummy data sent!");
                    Ok(())
                })
                .map_err(|e| error!("Connection error: {}", e));
            tokio::run(conn);
        }
        Some("NTCP2") => {
            let ntcp2 = transport::ntcp2::Engine::new();
            let conn = ntcp2
                .connect(peer_ri)
                .and_then(move |t| {
                    info!("Connection established!");
                    t.send(vec![transport::ntcp2::Block::DateTime(42)])
                })
                .and_then(|t| {
                    t.send(vec![transport::ntcp2::Block::Message(
                        i2np::Message::dummy_data(),
                    )])
                })
                .and_then(|_| {
                    info!("Dummy data sent!");
                    Ok(())
                })
                .map_err(|e| error!("Connection error: {}", e));
            tokio::run(conn);
        }
        Some(_) => panic!("Unknown transport specified"),
        None => panic!("No transport specified"),
    };
    0
}
