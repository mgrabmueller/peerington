// Copyright 2016 Martin Grabmueller. See the LICENSE file at the
// top-level directory of this distribution for license information.
//

/// Functions and data structures for reading a node configuration
/// from command line options and config files.

use getopts::Options;
use uuid::Uuid;
use toml;

use std::path::Path;
use std::fs::File;
use std::io::Read;

use super::error;

/// Print a usage summary to stdout that describes the command syntax.
pub fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} FILE [options]", program);
    print!("{}", opts.usage(&brief));
}

/// Configuration as parsed on the command line.
pub struct CmdLineConfig {
    /// UUID of the node.
    pub uuid: Option<Uuid>,
    /// The addresses this node will attempt to listen on.
    pub listen_addresses: Vec<String>,
    /// The addresses this node will use to connect to a cluster of
    /// peerington nodes.
    pub seed_addresses: Vec<String>,
    /// Local storage space where some data is stored during
    /// operation.
    pub workspace_dir: Option<String>,
    /// Location of the config file.
    pub config_file: Option<String>,
}

/// Configuration as parsed from config file.
pub struct FileConfig {
    /// UUID of the node.
    pub uuid: Option<Uuid>,
    /// The addresses this node will attempt to listen on.
    pub listen_addresses: Vec<String>,
    /// The addresses this node will use to connect to a cluster of
    /// peerington nodes.
    pub seed_addresses: Vec<String>,
    /// Local storage space where some data is stored during
    /// operation.
    pub workspace_dir: Option<String>
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

fn extract_config(value: &toml::Table) -> Result<FileConfig, error::ConfigError> {
    fn extract_string_list(node_table: &toml::Table,
                           field_name: &str) -> Vec<String> {
        node_table.get(field_name)
            .and_then(|la| la.as_slice())
            .and_then(|la| {
                let mut v = Vec::new();
                for s in la {
                    match s.as_str() {
                        None => {
                            error!("invalid {} entry in config file - ignoring",
                                   field_name);
                        },
                        Some(s) => v.push(String::from(s))
                    }
                };
                Some(v)
            })
            .or_else(|| {
                error!("invalid {} entry in config file - ignoring",
                       field_name);
                None
            }).unwrap_or(vec![])
    }
    value.get("node")
        .and_then(|node_config| node_config.as_table())
        .and_then(|node_table| {
            let workspace =
                node_table.get("workspace-directory")
                .and_then(|s| s.as_str())
                .or_else(|| {
                    error!("invalid workspace-directory entry in config file - ignoring");
                    None
                })
                .and_then(|s| Some(String::from(s)));

            let uuid =
                node_table.get("uuid")
                .and_then(|u| u.as_str())
                .or_else(|| {
                    error!("invalid uuid entry in config file - ignoring");
                    None
                })
                .and_then(|u|
                          Uuid::parse_str(u.chars().as_str())
                          .map_err(|e| {
                              error!("invalid uuid entry in config file: {} - ignoring", e);
                              e
                          }).ok());

            let listen_addresses = extract_string_list(node_table,
                                                       "listen-addresses");
            let seed_addresses = extract_string_list(node_table,
                                                     "seed-addresses");
            Some(FileConfig{
                workspace_dir: workspace,
                uuid: uuid,
                seed_addresses: seed_addresses,
                listen_addresses: listen_addresses})
        }).ok_or(error::ConfigError::InvalidConfig("required entry missing: node"))

}

/// Parse config file in TOML format. Either return a `FileConfig'
/// value or an error. Note that in config files, some values are
/// optional which are not optional on the command line.
pub fn parse_config<P: AsRef<Path>>(fname: P) -> Result<FileConfig, error::ConfigError> {
    let mut file = try!(File::open(fname));
    let mut s = String::new();
    try!(file.read_to_string(&mut s));
    let mut parser = toml::Parser::new(&s);

    match parser.parse() {
        None =>
            Err(error::ConfigError::Toml(parser.errors)),
        Some(ref value) => {
            extract_config(value)
        }
    }
}

/// Merges command line options and settings from a TOML config file
/// into a `Config' value.  Command line options have precedence, that
/// means that if a value is set both on the command line and in the
/// config file, the value on the command line is used.  Note
/// especially that lists of values (like listen and seed addresses)
/// are not appended.
pub fn merge_configs(cmd_config: &CmdLineConfig, file_config: &FileConfig) ->
    Result<Config, error::ConfigError>
{

    let workspace_dir =
        match cmd_config.workspace_dir {
            Some(ref d) =>
                d.clone(),
            None =>
                match file_config.workspace_dir {
                    Some(ref d) =>
                        d.clone(),
                    None =>
                        return Err(error::ConfigError::NoWorkspace)
                }
        };
    let uuid =
        match cmd_config.uuid {
            Some(u) => u,
            None =>
                match file_config.uuid {
                    Some(u) => u,
                    None => return Err(error::ConfigError::NoUuid)
                }
        };
    let listen_addresses =
        if cmd_config.listen_addresses.len() > 0 {
            cmd_config.listen_addresses.clone()
        } else if file_config.listen_addresses.len() > 0 {
            file_config.listen_addresses.clone()
        } else {
            return Err(error::ConfigError::NoListenAddress)
        };
    let seed_addresses =
        if cmd_config.seed_addresses.len() > 0 {
            cmd_config.seed_addresses.clone()
        } else {
            file_config.seed_addresses.clone()
        };
    Ok(Config{
        uuid: uuid,
        workspace_dir: workspace_dir,
        listen_addresses: listen_addresses,
        seed_addresses: seed_addresses,
    })
}

/// Parse allowed options for a peerington node.  Either return a
/// complete `Config' value or an error value.  Note that on the
/// command line, other values might be optional than in a config
/// file.
pub fn parse_opts(args: Vec<String>) -> Result<CmdLineConfig, error::ConfigError> {

    let mut opts = Options::new();
    opts.optopt("c", "config", "set config file", "FILE");
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

            let addresses = matches.opt_strs("l");

            let seeds = matches.opt_strs("s");

            let workspace = matches.opt_str("w");
            let config = matches.opt_str("c");
            match (workspace.clone(), config.clone()) {
                (None, None) =>
                    return Err(error::ConfigError::NoWorkspace),
                (_, _) => {
                }
            };

            let uuid =
                match matches.opt_str("u") {
                    Some(uuid) => {
                        match Uuid::parse_str(uuid.chars().as_str()) {
                            Ok(u) => {
                                Some(u)
                            }
                            Err(e) => {
                                return Err(error::ConfigError::InvalidUuid(e));
                            }
                        }
                    },
                    None => {
                        None
                    }
                };

            return Ok(CmdLineConfig {
                listen_addresses: addresses,
                seed_addresses: seeds,
                workspace_dir: workspace,
                config_file: config,
                uuid: uuid
            });
        }
        Err(f) => {
            return Err(error::ConfigError::GetOptError(f));
        }
    };
}

pub fn get_config(args: Vec<String>) ->
    Result<Config, error::ConfigError>
{
    match parse_opts(args) {
        Err(e) => Err(e),
        Ok(cmd_config) => {
            let path =
                match cmd_config.config_file {
                    Some(ref cf) => Path::new(cf).to_path_buf(),
                    None =>
                        match cmd_config.workspace_dir {
                            Some(ref wd) =>
                                Path::new(&wd.clone()).join("peerington.toml"),
                            None => {
                                // command line parsing ensures that
                                // at either a config file or a
                                // workspace directory is given.
                                panic!("the impossible has happened");
                            }
                        }
                };
            match parse_config(&path) {
                Err(e) => Err(e),
                Ok(file_config) => {
                    merge_configs(&cmd_config, &file_config)
                }
            }
        }
    }
}
