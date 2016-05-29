// Copyright 2016 The Martin Grabmueller. See the LICENSE file at the
// top-level directory of this distribution for license information.
//

extern crate uuid;
extern crate getopts;

use uuid::Uuid;
//use uuid::ParseError;
use getopts::Options;
//use getopts::Fail;
use std::fmt;
use std::io::Write;
use std::io::Read;
use std::net::TcpListener;
use std::net::TcpStream;
use std::thread;

/// Print a usage summary to stdout that describes the command syntax.
pub fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} FILE [options]", program);
    print!("{}", opts.usage(&brief));
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

/// Error values returned from the command line option parser.
pub enum ConfigError {
    /// The user has given the `-h' or `--help' options.
    HelpRequested(getopts::Options),
    /// No listen address was specified.
    NoListenAddress,
    /// No workspace directory was specified.
    NoWorkspace,
    /// No UUID was specified.
    NoUuid,
    /// The UUID given could not be parsed.
    InvalidUuid(uuid::ParseError),
    /// Some error during option parsing happened, for example an
    /// invalid option was given.
    GetOptError(getopts::Fail)
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ConfigError::HelpRequested(_) =>
                write!(f, "help requested"),
            ConfigError::NoListenAddress =>
                write!(f, "no listen address given"),
            ConfigError::NoWorkspace =>
                write!(f, "no workspace directory given"),
            ConfigError::NoUuid =>
                write!(f, "no node UUID given"),
            ConfigError::InvalidUuid(e) =>
                write!(f, "UUID is invalid: {}", e),
            ConfigError::GetOptError(ref e) =>
                write!(f, "{}", e)
        }
    }
}

/// Parse allowed options for a peerington node.  Either return a
/// complete `Config' value or an error value.
pub fn parse_opts(args: Vec<String>) -> Result<Config, ConfigError> {

    let mut opts = Options::new();
    opts.optopt("u", "uuid", "set node uuid", "UUID");
    opts.optopt("w", "workspace", "set workspace directory", "DIRECTORY");
    opts.optmulti("l", "listen", "set listen address(es)", "ADDRESS:PORT");
    opts.optmulti("s", "seed", "set seed address(es)", "ADDRESS:PORT");
    opts.optflag("h", "help", "print this help menu");

    match opts.parse(&args[1..]) {
        Ok(matches) => { 
            if matches.opt_present("h") {
                return Err(ConfigError::HelpRequested(opts));
            }

            let addresses = if matches.opt_present("l") {
                matches.opt_strs("l")
            } else {
                return Err(ConfigError::NoListenAddress);
            };

            let seeds = matches.opt_strs("s");

            let workspace =
                match matches.opt_str("w") {
                    Some(w) => w,
                    None => {
                        return Err(ConfigError::NoWorkspace);
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
                                return Err(ConfigError::InvalidUuid(e));
                            }
                        }
                    },
                    None => {
                        return Err(ConfigError::NoUuid);
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
            return Err(ConfigError::GetOptError(f));
        }
    };
}

fn handler(stream: &mut TcpStream) {
    if let Ok(peer) = stream.peer_addr() {
        println!("connection from {}", peer);
    } else {
        println!("connection attempt");
    }
    let mut buf = [33; 1024];
    loop {
        match stream.read(&mut buf) {
            Ok(0) =>
                break,
            Ok(n) => {
                match stream.write(&buf[0..n]) {
                    Ok(x) =>
                        if x != n {
                            println!("could not write everything");
                            break;
                        },
                    Err(e) => {
                        println!("error when writing: {}", e);
                    }
                }
            },
            Err(e) => {
                println!("error when reading: {}", e);
                break;
            }
        }
    }
}

fn listener(addr: String) {
    match TcpListener::bind(addr.as_str()) {
        Ok(listener) => {
            println!("listening on {}", listener.local_addr().unwrap());
            for stream in listener.incoming() {
                match stream {
                    Ok(mut stream) => {
                        thread::spawn(move || {
                            handler(&mut stream);
                        });
                    },
                    Err(e) =>
                        println!("error when accepting connection to {}: {}",
                                 addr, e)
                }
            }
        },
        Err(e) => {
            println!("error when binding to {}: {}", addr, e);
        }
    }
}

pub fn start_listeners(config: &Config) {
    for addr in config.listen_addresses.clone() {
        let a = addr.clone();
        thread::spawn(move || listener(a));
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
