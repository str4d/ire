#[macro_use]
extern crate log;

extern crate clap;
extern crate env_logger;
extern crate futures;
extern crate ire;
extern crate tokio;

use clap::{App, Arg, ArgMatches, SubCommand};
use futures::Future;
use ire::{data, i2np, transport};

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
                        )
                        .arg(
                            Arg::with_name("ntcp2Keys")
                                .help("Path to the server's NTCP2 keys")
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
    let ntcp2_keyfile = args.value_of("ntcp2Keys").unwrap();

    let ntcp = transport::ntcp::Engine::new(ntcp_addr);
    let ntcp2 = match transport::ntcp2::Engine::from_file(ntcp2_addr, ntcp2_keyfile) {
        Ok(ret) => ret,
        Err(_) => {
            let ret = transport::ntcp2::Engine::new(ntcp2_addr);
            ret.to_file(ntcp2_keyfile).unwrap();
            ret
        }
    };

    let mut ri = data::RouterInfo::new(rsk.rid.clone());
    ri.set_addresses(vec![ntcp.address(), ntcp2.address()]);
    ri.sign(&rsk.signing_private_key);
    ri.to_file(args.value_of("routerInfo").unwrap()).unwrap();

    // Accept all incoming sockets
    info!("NTCP:  Listening on {}", ntcp_addr);
    let listener = ntcp
        .listen(rsk.rid.clone(), rsk.signing_private_key.clone())
        .map_err(|e| error!("NTCP listener error: {}", e));

    info!("NTCP2: Listening on {}", ntcp2_addr);
    let listener2 = ntcp2
        .listen(rsk.rid)
        .map_err(|e| error!("NTCP2 listener error: {}", e));

    tokio::run(ntcp.join4(ntcp2, listener, listener2).map(|_| ()));
    0
}

fn cli_client(args: &ArgMatches) -> i32 {
    let rsk = data::RouterSecretKeys::from_file(args.value_of("routerKeys").unwrap()).unwrap();
    let peer_ri = data::RouterInfo::from_file(args.value_of("peerInfo").unwrap()).unwrap();
    let hash = peer_ri.router_id.hash();

    let mut ri = data::RouterInfo::new(rsk.rid.clone());
    ri.sign(&rsk.signing_private_key);

    info!("Connecting to {}", peer_ri.router_id.hash());
    match args.value_of("transport") {
        Some("NTCP") => {
            let ntcp = transport::ntcp::Engine::new("127.0.0.1:0".parse().unwrap());
            let handle = ntcp.handle();
            let conn = ntcp
                .connect(rsk.rid, rsk.signing_private_key, peer_ri)
                .and_then(move |_| handle.timestamp(hash.clone(), 42).map(|_| (handle, hash)))
                .and_then(|(handle, hash)| handle.send(hash, i2np::Message::dummy_data()))
                .and_then(|_| {
                    info!("Dummy data sent!");
                    Ok(())
                })
                .map_err(|e| error!("Connection error: {}", e));
            tokio::run(ntcp.join(conn).map(|_| ()));
        }
        Some("NTCP2") => {
            let ntcp2 = transport::ntcp2::Engine::new("127.0.0.1:0".parse().unwrap());
            let handle = ntcp2.handle();
            let conn = ntcp2
                .connect(ri, peer_ri)
                .unwrap()
                .and_then(move |_| {
                    info!("Connection established!");
                    handle.timestamp(hash.clone(), 42).map(|_| (handle, hash))
                })
                .and_then(|(handle, hash)| handle.send(hash, i2np::Message::dummy_data()))
                .and_then(|_| {
                    info!("Dummy data sent!");
                    Ok(())
                })
                .map_err(|e| error!("Connection error: {}", e));
            tokio::run(ntcp2.join(conn).map(|_| ()));
        }
        Some(_) => panic!("Unknown transport specified"),
        None => panic!("No transport specified"),
    };
    0
}
