// Copyright 2016 Martin Grabmueller. See the LICENSE file at the
// top-level directory of this distribution for license information.
//

#[macro_use]
extern crate log;
extern crate uuid;
extern crate getopts;
extern crate openssl;

use uuid::Uuid;
use getopts::Options;
use openssl::ssl;
use openssl::nid;
use openssl::x509;
use openssl::x509::X509ValidationError::*;

use std::sync::Arc;
use std::sync::Mutex;
use std::collections::BTreeMap;
use std::io;
use std::io::Read;
use std::io::Write;
use std::net::TcpListener;
use std::net::TcpStream;
use std::thread;

pub mod error;

/// Print a usage summary to stdout that describes the command syntax.
pub fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} FILE [options]", program);
    print!("{}", opts.usage(&brief));
}

pub struct NodeState {
    pub ssl_context: ssl::SslContext,
    pub node_map: Arc<Mutex<BTreeMap<String, Uuid>>>
}

fn verify_client_cert(preverify_ok: bool, x509_ctx: &x509::X509StoreContext) -> bool {
    if preverify_ok {
         return true;
    } else {
        let err =
            match x509_ctx.get_error() {
                Some(e) =>
                    match e {
                        X509UnableToGetIssuerCert => "X509UnableToGetIssuerCert",
                        X509UnableToGetCrl => "X509UnableToGetCrl",
                        X509UnableToDecryptCertSignature => "X509UnableToDecryptCertSignature",
                        X509UnableToDecryptCrlSignature => "X509UnableToDecryptCrlSignature",
                        X509UnableToDecodeIssuerPublicKey => "X509UnableToDecodeIssuerPublicKey",
                        X509CertSignatureFailure => "X509CertSignatureFailure",
                        X509CrlSignatureFailure => "X509CrlSignatureFailure",
                        X509CertNotYetValid => "X509CertNotYetValid",
                        X509CertHasExpired => "X509CertHasExpired",
                        X509CrlNotYetValid => "X509CrlNotYetValid",
                        X509CrlHasExpired => "X509CrlHasExpired",
                        X509ErrorInCertNotBeforeField => "X509ErrorInCertNotBeforeField",
                        X509ErrorInCertNotAfterField => "X509ErrorInCertNotAfterField",
                        X509ErrorInCrlLastUpdateField => "X509ErrorInCrlLastUpdateField",
                        X509ErrorInCrlNextUpdateField => "X509ErrorInCrlNextUpdateField",
                        X509OutOfMem => "X509OutOfMem",
                        X509DepthZeroSelfSignedCert => "X509DepthZeroSelfSignedCert",
                        X509SelfSignedCertInChain => "X509SelfSignedCertInChain",
                        X509UnableToGetIssuerCertLocally => "X509UnableToGetIssuerCertLocally",
                        X509UnableToVerifyLeafSignature => "X509UnableToVerifyLeafSignature",
                        X509CertChainTooLong => "X509CertChainTooLong",
                        X509CertRevoked => "X509CertRevoked",
                        X509InvalidCA => "X509InvalidCA",
                        X509PathLengthExceeded => "X509PathLengthExceeded",
                        X509InvalidPurpose => "X509InvalidPurpose",
                        X509CertUntrusted => "X509CertUntrusted",
                        X509CertRejected => "X509CertRejected",
                        X509SubjectIssuerMismatch => "X509SubjectIssuerMismatch",
                        X509AkidSkidMismatch => "X509AkidSkidMismatch",
                        X509AkidIssuerSerialMismatch => "X509AkidIssuerSerialMismatch",
                        X509KeyusageNoCertsign => "X509KeyusageNoCertsign",
                        X509UnableToGetCrlIssuer => "X509UnableToGetCrlIssuer",
                        X509UnhandledCriticalExtension => "X509UnhandledCriticalExtension",
                        X509KeyusageNoCrlSign => "X509KeyusageNoCrlSign",
                        X509UnhandledCriticalCrlExtension => "X509UnhandledCriticalCrlExtension",
                        X509InvalidNonCA => "X509InvalidNonCA",
                        X509ProxyPathLengthExceeded => "X509ProxyPathLengthExceeded",
                        X509KeyusageNoDigitalSignature => "X509KeyusageNoDigitalSignature",
                        X509ProxyCertificatesNotAllowed => "X509ProxyCertificatesNotAllowed",
                        X509InvalidExtension => "X509InvalidExtension",
                        X509InavlidPolicyExtension => "X509InavlidPolicyExtension",
                        X509NoExplicitPolicy => "X509NoExplicitPolicy",
                        X509DifferentCrlScope => "X509DifferentCrlScope",
                        X509UnsupportedExtensionFeature => "X509UnsupportedExtensionFeature",
                        X509UnnestedResource => "X509UnnestedResource",
                        X509PermittedVolation => "X509PermittedVolation",
                        X509ExcludedViolation => "X509ExcludedViolation",
                        X509SubtreeMinmax => "X509SubtreeMinmax",
                        X509UnsupportedConstraintType => "X509UnsupportedConstraintType",
                        X509UnsupportedConstraintSyntax => "X509UnsupportedConstraintSyntax",
                        X509UnsupportedNameSyntax => "X509UnsupportedNameSyntax",
                        X509CrlPathValidationError => "X509CrlPathValidationError",
                        X509ApplicationVerification => "X509ApplicationVerification",
                        X509UnknownError(_i) => "X509UnknownError"
                    },
                None => "no error"
            };
        
        error!("client certificate check failed at depth {}: {}", x509_ctx.error_depth(), err);

        return false;
    }
}

impl NodeState {
    pub fn new(config: &Config) -> Result<NodeState, error::Error> {
        let mut ssl_context = try!(ssl::SslContext::new(ssl::SslMethod::Tlsv1));

        let mut ca_path = config.workspace_dir.clone();
        ca_path.push_str("/ca-chain.cert.pem");

        trace!("setting ca file");
        try!(ssl_context.set_CA_file(&ca_path));
   
        let mut cert_path = config.workspace_dir.clone();
        cert_path.push_str("/");
        cert_path.push_str(&config.uuid.to_string());
        cert_path.push_str(".cert.pem");

        trace!("setting certificate file");
        try!(ssl_context.set_certificate_file(&cert_path, x509::X509FileType::PEM));
   
        let mut priv_key_path = config.workspace_dir.clone();
        priv_key_path.push_str("/");
        priv_key_path.push_str(&config.uuid.to_string());
        priv_key_path.push_str(".key.pem");

        trace!("setting private key file");
        try!(ssl_context.set_private_key_file(&priv_key_path,
                                              x509::X509FileType::PEM));
        try!(ssl_context.check_private_key());

        ssl_context.set_verify(ssl::SSL_VERIFY_PEER
                               | ssl::SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                               Some(verify_client_cert));

        let node_map = BTreeMap::new();
        Ok(NodeState {
            ssl_context: ssl_context,
            node_map: Arc::new(Mutex::new(node_map))
        })
    }
}

/// Configuration of a peerington node.
pub struct Config {
    /// UUID of the node.
    pub uuid: Uuid,
    /// The addresses this node will attempt to listen on.
    pub listen_addresses: Vec<String>,
    /// The addresses this node will use to connect to a cluster of
    /// peerington nodes.
    pub seed_addresses: Vec<String>,
    /// Local storage space where some data is stored during
    /// operation.
    pub workspace_dir: String
}

/// Parse allowed options for a peerington node.  Either return a
/// complete `Config' value or an error value.
pub fn parse_opts(args: Vec<String>) -> Result<Config, error::ConfigError> {

    let mut opts = Options::new();
    opts.optopt("u", "uuid", "set node uuid", "UUID");
    opts.optopt("w", "workspace", "set workspace directory", "DIRECTORY");
    opts.optmulti("l", "listen", "set listen address(es)", "ADDRESS:PORT");
    opts.optmulti("s", "seed", "set seed address(es)", "ADDRESS:PORT");
    opts.optflag("h", "help", "print this help menu");

    match opts.parse(&args[1..]) {
        Ok(matches) => { 
            if matches.opt_present("h") {
                return Err(error::ConfigError::HelpRequested(opts));
            }

            let addresses = if matches.opt_present("l") {
                matches.opt_strs("l")
            } else {
                return Err(error::ConfigError::NoListenAddress);
            };

            let seeds = matches.opt_strs("s");

            let workspace =
                match matches.opt_str("w") {
                    Some(w) => w,
                    None => {
                        return Err(error::ConfigError::NoWorkspace);
                    }
                };

            let uuid =
                match matches.opt_str("u") {
                    Some(uuid) => {
                        match Uuid::parse_str(uuid.chars().as_str()) {
                            Ok(u) => {
                                u
                            }
                            Err(e) => {
                                return Err(error::ConfigError::InvalidUuid(e));
                            }
                        }
                    },
                    None => {
                        return Err(error::ConfigError::NoUuid);
                    }
                };

            return Ok(Config {
                listen_addresses: addresses,
                seed_addresses: seeds,
                workspace_dir: workspace,
                uuid: uuid
            });
        }
        Err(f) => {
            return Err(error::ConfigError::GetOptError(f));
        }
    };
}

fn handler_loop(_node_state: Arc<NodeState>, stream: &mut ssl::SslStream<TcpStream>) {
    let mut buf = [33; 1024];
    loop {
        match stream.ssl_read(&mut buf) {
            Ok(0) =>
                break,
            Ok(n) => {
                io::stdout().write(&buf[0..n]).unwrap();
                match stream.ssl_write(&buf[0..n]) {
                    Ok(x) =>
                        if x != n {
                            error!("could not write everything");
                            break;
                        },
                    Err(e) => {
                        error!("error when writing: {}", e);
                        break;
                    }
                }
            },
            Err(e) => {
                error!("error when reading: {}", e);
                break;
            }
        }
    }
}

fn get_peer_uuid(stream: &ssl::SslStream<TcpStream>) -> Option<Uuid> {
    if let Some(peer_cert) = stream.ssl().peer_certificate() {
        let name = peer_cert.subject_name();
        if let Some(peer_name) = name.text_by_nid(nid::Nid::CN) {
            match Uuid::parse_str(&peer_name) {
                Ok(u) => {
                    Some(u)
                },
                Err(e) => {
                    error!("peer's CN is not a valid UUID: {}.", e);
                    None
                }
            }
        } else {
            error!("no name CN in peer certificate.");
            None
        }
    } else {
        error!("cannot get peer certificate, closing connection.");
        None
    }
}

/// Handle an established TLS connection.  The UUID of the peer is
/// taken from the peer certificate.
fn handler(node_state: Arc<NodeState>, stream: &mut ssl::SslStream<TcpStream>) {
    if let Ok(peer) = stream.get_ref().peer_addr() {
        info!("connected to {}", peer);
        match get_peer_uuid(stream) {
            Some(u) => {
                info!("UUID of peer: {}", u);
                let inserted =
                    match node_state.node_map.lock() {
                        Ok(mut node_map) => {
                            node_map.insert(u.to_string(), u);
                            true
                        }
                        Err(_) => {
                            error!("cannot lock node map");
                            false
                        }
                    };
                if inserted {
                    handler_loop(node_state.clone(), stream);
                    match node_state.node_map.lock() {
                        Ok(mut node_map) => {
                            node_map.remove(&u.to_string());
                            ()
                        }
                        Err(_) => {
                            error!("cannot lock node map");
                        }
                    }
                }
            }
            None => {
                ()
            }
        }
        info!("{} disconnected", peer);
    } else {
        error!("cannot determine peer address, closing connection.");
    }
}

/// Bind to the given address and wait for incoming connections, using
/// the context to establish TLS connections.  Call the handler
/// function for each connection.
fn listener(node_state: Arc<NodeState>, addr: String) {
    match TcpListener::bind(addr.as_str()) {
        Ok(listener) => {
            info!("listening on {}", listener.local_addr().unwrap());
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        let ns = node_state.clone();
                        let a = addr.clone();
                        thread::spawn(move || {
                            match ssl::Ssl::new(&ns.ssl_context) {
                                Ok(ssl) => {
                                    match ssl::SslStream::accept(ssl, stream) {
                                        Ok(mut ssl_stream) => {
                                            handler(ns, &mut ssl_stream);
                                        },
                                        Err(e) => {
                                            error!("error when accepting connection: {}",
                                                   e)
                                        }
                                    }
                                }
                                Err(e) => {
                                    error!("error when accepting connection to {}: {}",
                                           a, e)
                                }
                            }
                        });
                        ()
                    },
                    Err(e) =>
                        error!("error when accepting connection to {}: {}",
                                 addr, e)
                }
            }
        },
        Err(e) => {
            error!("error when binding to {}: {}", addr, e);
        }
    }
}

/// Connect to the given address, using the context to establish a TLS
/// connection.  Call the handler function when connected.
fn connector(node_state: Arc<NodeState>, addr: String) {
    match TcpStream::connect(addr.as_str()) {
        Ok(stream) => {
            match ssl::Ssl::new(&node_state.ssl_context) {
                Ok(ssl) => {
                    thread::spawn(move || {
                        match ssl::SslStream::connect(ssl, stream) {
                            Ok(mut ssl_stream) => {
                                handler(node_state, &mut ssl_stream);
                            },
                            Err(e) => {
                                error!("error when accepting connection: {}",
                                       e)
                            }
                        }
                    });
                    ()
                },
                Err(e) => {
                    error!("error when establishing TLS connection to {}: {}",
                           addr, e)
                }
            }
        },
        Err(e) =>
            error!("error when connecting to {}: {}",
                   addr, e)
    }
}

pub fn start_listeners(config: &Config, node_state: Arc<NodeState>) {
    for addr in config.listen_addresses.clone() {
        let a = addr.clone();
        let ns = node_state.clone();
        thread::spawn(move || listener(ns, a));
    }
}

pub fn connect_seeds(config: &Config, node_state: Arc<NodeState>) {
    for addr in config.seed_addresses.clone() {
        let a = addr.clone();
        let ns = node_state.clone();
        thread::spawn(move || connector(ns, a));
    }
}

mod test {
    #[allow(unused_imports)]
    use super::*;
    
    #[test]
    fn no_listen() {
        let ok = match parse_opts(vec!["prog".to_string()]) {
            Err(ConfigError::NoListenAddress) => true,
            _ => false
        };
        assert!(ok);
    }

    #[test]
    fn no_workspace() {
        let ok = match parse_opts(vec!["prog".to_string(),
                                       "--listen=localhost:1234".to_string()]) {
            Err(ConfigError::NoWorkspace) => true,
            _ => false
        };
        assert!(ok);
    }

    #[test]
    fn no_uuid() {
        let ok = match parse_opts(vec!["prog".to_string(),
                                       "--listen=localhost:1234".to_string(),
                                       "--workspace=space".to_string()]) {
            Err(ConfigError::NoUuid) => true,
            _ => false
        };
        assert!(ok);
    }

    #[test]
    fn invalid_uuid() {
        let ok = match parse_opts(vec!["prog".to_string(),
                                       "--listen=localhost:1234".to_string(),
                                       "--workspace=space".to_string(),
                                       "--uuid=abcde".to_string()]) {
            Err(ConfigError::InvalidUuid(_)) => true,
            _ => false
        };
        assert!(ok);
    }

    #[test]
    fn invalid_arg() {
        let ok = match parse_opts(vec!["prog".to_string(), "--hepl".to_string()]) {
            Err(ConfigError::GetOptError(_)) => true,
            _ => false
        };
        assert!(ok);
    }

    #[test]
    fn help_arg() {
        let ok = match parse_opts(vec!["prog".to_string(), "-h".to_string()]) {
            Err(ConfigError::HelpRequested(_)) => true,
            _ => false
        };
        assert!(ok);
    }

    #[test]
    fn long_help_arg() {
        let ok = match parse_opts(vec!["prog".to_string(), "--help".to_string()]) {
            Err(ConfigError::HelpRequested(_)) => true,
            _ => false
        };
        assert!(ok);
    }

    #[test]
    fn all_fine() {
        match parse_opts(vec!["prog".to_string(),
                              "--listen=localhost:1234".to_string(),
                              "--workspace=space".to_string(),
                              "--uuid=33d92212-7bf3-4573-8052-17789f520240".to_string()]) {
            Ok(config) => {
                assert!(config.listen_addresses.len() >= 1);
                for a in config.listen_addresses {
                    assert!(a.len() > 0);
                }
                assert!(config.workspace_dir.len() >= 1);
            }
            _ => {
                assert!(false);
            }
        };
    }

}
