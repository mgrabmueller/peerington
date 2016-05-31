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
use openssl::x509;

use std::io::Write;
use std::io::Read;
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
    pub ssl_context: ssl::SslContext
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
        
        Ok(NodeState {
            ssl_context: ssl_context
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

fn handler(stream: &mut ssl::SslStream<TcpStream>) {
    if let Ok(peer) = stream.get_ref().peer_addr() {
        info!("connection from {}", peer);
    } else {
        info!("connection attempt");
    }
    let mut buf = [33; 1024];
    loop {
        match stream.ssl_read(&mut buf) {
            Ok(0) =>
                break,
            Ok(n) => {
                match stream.ssl_write(&buf[0..n]) {
                    Ok(x) =>
                        if x != n {
                            error!("could not write everything");
                            break;
                        },
                    Err(e) => {
                        error!("error when writing: {}", e);
                    }
                }
            },
            Err(e) => {
                error!("error when reading: {}", e);
                break;
            }
        }
    }
    if let Ok(peer) = stream.get_ref().peer_addr() {
        info!("closed connection from {}", peer);
    } else {
        info!("closed connection");
    }
}

fn listener(addr: String, ssl_context: &ssl::SslContext) {
    match TcpListener::bind(addr.as_str()) {
        Ok(listener) => {
            info!("listening on {}", listener.local_addr().unwrap());
            for stream in listener.incoming() {
                match stream {
                    Ok(mut stream) => {
                        match ssl::Ssl::new(ssl_context) {
                            Ok(ssl) => {
                                thread::spawn(move || {
                                    match ssl::SslStream::connect(ssl, stream) {
                                        Ok(mut ssl_stream) => {
                                            handler(&mut ssl_stream);
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
                                error!("error when accepting connection to {}: {}",
                                       addr, e)
                            }
                        }
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

pub fn start_listeners(config: &Config, ssl_context: &ssl::SslContext) {
    for addr in config.listen_addresses.clone() {
        let a = addr.clone();
        let ssl_ctx = ssl_context.clone();
        thread::spawn(move || listener(a, &ssl_ctx));
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
