#[macro_use]
extern crate log;

extern crate clap;
extern crate env_logger;
extern crate futures;
extern crate ire;
extern crate tokio;

use clap::{App, Arg, ArgMatches, SubCommand};
use futures::{Future, Stream};
use ire::{
    data, i2np,
    netdb::reseed::HttpsReseeder,
    router::{mock::mock_context, Builder},
    transport,
};

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
            SubCommand::with_name("router").arg(
                Arg::with_name("cfgFile")
                    .help("Path to the router's TOML config file")
                    .required(true),
            ),
        ).subcommand(
            SubCommand::with_name("cli")
                .subcommand(
                    SubCommand::with_name("gen").arg(
                        Arg::with_name("routerKeys")
                            .help("Path to write the router.keys.dat to")
                            .required(true),
                    ),
                ).subcommand(
                    SubCommand::with_name("client")
                        .arg(
                            Arg::with_name("routerKeys")
                                .help("Path to the client's router.keys.dat")
                                .required(true),
                        ).arg(
                            Arg::with_name("peerInfo")
                                .help("Path to the peer's router.info file")
                                .required(true),
                        ).arg(
                            Arg::with_name("transport")
                                .help("Transport to test")
                                .possible_values(&["NTCP", "NTCP2"])
                                .required(true),
                        ),
                ).subcommand(SubCommand::with_name("reseed")),
        ).get_matches();

    match matches.subcommand() {
        ("router", Some(matches)) => cli_router(matches),
        ("cli", Some(matches)) => match matches.subcommand() {
            ("gen", Some(matches)) => cli_gen(matches),
            ("client", Some(matches)) => cli_client(matches),
            ("reseed", Some(_)) => cli_reseed(),
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

fn cli_router(args: &ArgMatches) -> i32 {
    let builder = Builder::new();

    let builder = if let Some(cfg_file) = args.value_of("cfgFile") {
        builder.config_file(cfg_file.to_string())
    } else {
        builder
    };

    let mut r = builder.build().unwrap();

    let runner = r.start();

    tokio::run(runner.map_err(|_| ()));
    0
}

fn cli_client(args: &ArgMatches) -> i32 {
    let rsk = data::RouterSecretKeys::from_file(args.value_of("routerKeys").unwrap()).unwrap();
    let peer_ri = data::RouterInfo::from_file(args.value_of("peerInfo").unwrap()).unwrap();

    let mut ri = data::RouterInfo::new(rsk.rid.clone());
    ri.sign(&rsk.signing_private_key);

    info!("Connecting to {}", peer_ri.router_id.hash());
    match args.value_of("transport") {
        Some("NTCP") => {
            let (ntcp, mut engine) = transport::ntcp::Manager::new("127.0.0.1:0".parse().unwrap());
            engine.set_context(mock_context());
            let handle = ntcp.handle();
            let conn = ntcp
                .connect(rsk.rid, rsk.signing_private_key, peer_ri.clone())
                .and_then(move |_| {
                    handle
                        .timestamp(peer_ri.clone(), 42)
                        .map(|_| (handle, peer_ri))
                }).and_then(|(handle, peer)| handle.send(peer, i2np::Message::dummy_data()))
                .and_then(|_| {
                    info!("Dummy data sent!");
                    Ok(())
                }).map_err(|e| error!("Connection error: {}", e));
            tokio::run(
                engine
                    .into_future()
                    .map(|_| ())
                    .map_err(|_| ())
                    .join(conn)
                    .map(|_| ()),
            );
        }
        Some("NTCP2") => {
            let (ntcp2, mut engine) =
                transport::ntcp2::Manager::new("127.0.0.1:0".parse().unwrap());
            engine.set_context(mock_context());
            let handle = ntcp2.handle();
            let conn = ntcp2
                .connect(&ri, peer_ri.clone())
                .unwrap()
                .and_then(move |_| {
                    info!("Connection established!");
                    handle
                        .timestamp(peer_ri.clone(), 42)
                        .map(|_| (handle, peer_ri))
                }).and_then(|(handle, peer)| handle.send(peer, i2np::Message::dummy_data()))
                .and_then(|_| {
                    info!("Dummy data sent!");
                    Ok(())
                }).map_err(|e| error!("Connection error: {}", e));
            tokio::run(
                engine
                    .into_future()
                    .map(|_| ())
                    .map_err(|_| ())
                    .join(conn)
                    .map(|_| ()),
            );
        }
        Some(_) => panic!("Unknown transport specified"),
        None => panic!("No transport specified"),
    };
    0
}

fn cli_reseed() -> i32 {
    let reseeder = HttpsReseeder::new().and_then(|ri| {
        println!("Received {} RouterInfos", ri.len());
        Ok(())
    });
    tokio::run(reseeder);
    0
}
