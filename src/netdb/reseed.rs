use futures::{future, Async, Future, Poll};
use native_tls::{Certificate, TlsConnector};
use rand::{thread_rng, Rng};
use std::collections::HashMap;
use std::io;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use tokio_io::{self, IoFuture};
use tokio_tcp::TcpStream;
use tokio_tls;

use crypto::{OfflineSigningPublicKey, SigType};
use data::{Hash, RouterInfo};
use file::{Su3Content, Su3File};
use i2np::{DatabaseLookup, DatabaseLookupType};
use router::Context;

// newest first, please add new ones at the top
//
// ((url, port), path)                      // certificates/reseed/      // certificates/ssl/          // notes
// ----------------------------------       ------------------------     -------------------------     ---------------
#[cfg_attr(rustfmt, rustfmt_skip)]
const DEFAULT_RESEED_HOSTS: [((&str, u16), &str); 12] = [
    (("i2p.novg.net", 443), "/"),           // igor_at_novg.net.crt      // CA
    (("i2pseed.creativecowpat.net", 8443), "/"), // creativecowpat_at_mail.i2p.crt // i2pseed.creativecowpat.net.crt
    (("itoopie.atomike.ninja", 443), "/"),  // atomike_at_mail.i2p.crt   // CA
    (("reseed.onion.im", 443), "/"),        // lazygravy_at_mail.i2p     // reseed.onion.im.crt
    (("reseed.memcpy.io", 443), "/"),       // hottuna_at_mail.i2p.crt   // CA                         // SNI required
    (("reseed.atomike.ninja", 443), "/"),   // atomike_at_mail.i2p.crt   // CA                         // SNI required
    (("i2p.manas.ca", 8443), "/"),          // zmx_at_mail.i2p.crt       // CA                         // SNI required
    (("i2p-0.manas.ca", 8443), "/"),        // zmx_at_mail.i2p.crt       // CA                         // SNI required
    (("i2p.mooo.com", 443), "/netDb/"),     // bugme_at_mail.i2p.crt     // i2p.mooo.com.crt
    (("download.xxlspeed.com", 443), "/"),  // backup_at_mail.i2p.crt    // CA
    (("netdb.i2p2.no", 443), "/"),          // meeh_at_mail.i2p.crt      // CA                         // SNI required
    (("reseed.i2p-projekt.de", 443), "/"),  // echelon_at_mail.i2p.crt   // echelon.reseed2017.crt
];

macro_rules! reseed_cert {
    ($m:ident, $name:expr, $sig_type:ident, $der_file:expr) => {
        $m.insert(
            $name,
            OfflineSigningPublicKey::from_bytes(
                SigType::$sig_type,
                include_bytes!(concat!("../../assets/certificates/reseed/", $der_file)),
            ).unwrap(),
        );
    };
}

macro_rules! reseed_4096 {
    ($m:ident, $name:expr, $der_file:expr) => {
        reseed_cert!($m, $name, Rsa4096Sha512, $der_file)
    };
}

lazy_static! {
    pub(crate) static ref RESEED_SIGNERS: HashMap<&'static str, OfflineSigningPublicKey> = {
        let mut m = HashMap::new();
        reseed_4096!(m, "atomike@mail.i2p", "atomike_at_mail.i2p.der");
        reseed_4096!(m, "backup@mail.i2p", "backup_at_mail.i2p.der");
        reseed_4096!(m, "bugme@mail.i2p", "bugme_at_mail.i2p.der");
        reseed_4096!(
            m,
            "creativecowpat@mail.i2p",
            "creativecowpat_at_mail.i2p.der"
        );
        reseed_4096!(m, "echelon@mail.i2p", "echelon_at_mail.i2p.der");
        reseed_4096!(m, "hottuna@mail.i2p", "hottuna_at_mail.i2p.der");
        reseed_4096!(m, "igor@novg.net", "igor_at_novg.net.der");
        reseed_4096!(m, "lazygravy@mail.i2p", "lazygravy_at_mail.i2p.der");
        reseed_4096!(m, "meeh@mail.i2p", "meeh_at_mail.i2p.der");
        reseed_4096!(m, "zmx@mail.i2p", "zmx_at_mail.i2p.der");
        m
    };
}

const SSL_CERT_CREATIVECOWPAT_NET: &[u8; 948] =
    include_bytes!("../../assets/certificates/ssl/i2pseed.creativecowpat.net.crt");
const SSL_CERT_ONION_IM: &[u8; 2216] =
    include_bytes!("../../assets/certificates/ssl/reseed.onion.im.crt");
const SSL_CERT_MOOO_COM: &[u8; 1359] =
    include_bytes!("../../assets/certificates/ssl/i2p.mooo.com.crt");
const SSL_CERT_ECHELON: &[u8; 1452] =
    include_bytes!("../../assets/certificates/ssl/echelon.reseed2017.crt");

const MIN_RI_WANTED: usize = 100;
const MIN_RESEED_SERVERS: usize = 2;

fn reseed_from_host(
    cx: &TlsConnector,
    (host, path): ((&'static str, u16), &'static str),
) -> IoFuture<Su3File> {
    debug!("Reseeding from {}:{}", host.0, host.1);
    let addr = host.to_socket_addrs().unwrap().next().unwrap();

    let socket = TcpStream::connect(&addr);
    let cx = tokio_tls::TlsConnector::from(cx.clone());

    Box::new(
        socket
            .and_then(move |socket| {
                cx.connect(host.0, socket)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
            }).and_then(move |socket| {
                tokio_io::io::write_all(
                    socket,
                    format!(
                        "\
                         GET {}i2pseeds.su3 HTTP/1.0\r\n\
                         Host: {}\r\n\
                         User-Agent: Wget/1.11.4\r\n\
                         \r\n\
                         ",
                        path, host.0
                    ),
                )
            }).and_then(|(socket, _)| tokio_io::io::read_to_end(socket, Vec::new()))
            .and_then(|(_, data)| {
                Su3File::from_http_data(&data, &RESEED_SIGNERS).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Invalid SU3 file: {:?}", e),
                    )
                })
            }),
    )
}

/// Fetches RouterInfos from reseed servers via HTTPS.
pub struct HttpsReseeder {
    ctx: Arc<Context>,
    cx: TlsConnector,
    pending: Vec<((&'static str, u16), &'static str)>,
    active: IoFuture<Su3File>,
    succeeded: usize,
    fetched: usize,
    valid: usize,
}

impl HttpsReseeder {
    pub fn new(ctx: Arc<Context>) -> Self {
        // Build TLS context with the necessary self-signed certificates
        let mut cx = TlsConnector::builder();
        cx.add_root_certificate(Certificate::from_pem(SSL_CERT_CREATIVECOWPAT_NET).unwrap());
        cx.add_root_certificate(Certificate::from_pem(SSL_CERT_ONION_IM).unwrap());
        cx.add_root_certificate(Certificate::from_pem(SSL_CERT_MOOO_COM).unwrap());
        cx.add_root_certificate(Certificate::from_pem(SSL_CERT_ECHELON).unwrap());
        let cx = cx.build().unwrap();

        let mut hosts: Vec<_> = DEFAULT_RESEED_HOSTS.to_vec();
        thread_rng().shuffle(&mut hosts);
        let active = reseed_from_host(&cx, hosts.swap_remove(0));

        HttpsReseeder {
            ctx,
            cx,
            pending: hosts,
            active,
            succeeded: 0,
            fetched: 0,
            valid: 0,
        }
    }
}

impl Future for HttpsReseeder {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            // Check the currently-active reseed request
            match self.active.poll() {
                Ok(Async::Ready(su3)) => match su3.content {
                    Su3Content::Reseed(new_ri) => {
                        self.succeeded += 1;
                        self.fetched += new_ri.len();

                        let mut db = self.ctx.netdb.write().unwrap();
                        for ri in new_ri {
                            let hash = ri.router_id.hash();
                            if let Err(e) = db.store_router_info(hash.clone(), ri) {
                                error!("Invalid RouterInfo {} received from reseed: {}", hash, e);
                            } else {
                                self.valid += 1;
                            }
                        }

                        // Check if we are done reseeding
                        if self.valid >= MIN_RI_WANTED && self.succeeded >= MIN_RESEED_SERVERS {
                            info!(
                                "Fetched {} RouterInfos from {} servers ({} valid)",
                                self.fetched, self.succeeded, self.valid
                            );
                            return Ok(Async::Ready(()));
                        }
                    }
                },
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                Err(e) => error!("Error while reseeding: {}", e),
            }

            // If we reach here, the active reseed has finished
            if self.pending.is_empty() {
                if self.valid == 0 {
                    error!("Failed to reseed from any server");
                    return Err(());
                } else {
                    info!(
                        "Fetched {} RouterInfos from {} servers ({} valid)",
                        self.fetched, self.succeeded, self.valid
                    );
                    return Ok(Async::Ready(()));
                }
            } else {
                self.active = reseed_from_host(&self.cx, self.pending.swap_remove(0));
            }
        }
    }
}

/// Fetch RouterInfos from a specified floodfill.
///
/// We send DatabaseLookup messages for random keys with both RouterInfo and
/// exploratory lookup types:
/// - The RouterInfo lookups will result either in DatabaseStore messages (if we
///   are lucky), or DatabaseSearchReply messages containing router hashes that
///   with high probability are for floodfills.
/// - The exploratory lookups will result in DatabaseSearchReply messages that
///   are guaranteed to only contain router hashes for non-floodfill routers.
///
/// The DatabaseSearchReply messages then trigger lookups of the corresponding
/// RouterInfos from the same specified floodfill.
pub fn reseed_from_floodfill(
    ctx: Arc<Context>,
    ff: RouterInfo,
) -> Result<impl Future<Item = (), Error = ()>, ()> {
    let mut key = Hash([0u8; 32]);
    let from = ctx.keys.rid.hash();

    Ok(future::join_all(
        (0..20)
            .map(|_| DatabaseLookupType::RouterInfo)
            .chain((0..40).map(|_| DatabaseLookupType::Exploratory))
            .map(move |lookup_type| {
                // Pick a random key to search for
                thread_rng().fill(&mut key.0);
                let dlm =
                    DatabaseLookup::create_msg(key.clone(), from.clone(), lookup_type, vec![]);
                ctx.comms
                    .read()
                    .unwrap()
                    .send(ff.clone(), dlm)
                    .map_err(|_| ())
            }),
    ).map(|_| ()))
}
