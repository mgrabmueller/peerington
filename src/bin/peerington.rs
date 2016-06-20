extern crate peerington;
extern crate env_logger;
extern crate uuid;

use peerington::parse_opts;
use peerington::parse_config;
use peerington::merge_configs;
use peerington::print_usage;
use peerington::error::ConfigError;
use peerington::Config;
use peerington::NodeState;
use peerington::Message;
use peerington::start_listeners;
use peerington::connect_seeds;
use peerington::send_message;

use uuid::Uuid;

use std::path::Path;
use std::sync::mpsc::sync_channel;
use std::sync::Arc;
use std::env;
use std::io;
use std::io::Write;
use std::fmt;
use std::thread;

fn main() {
    env_logger::init().unwrap();

    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();


    match parse_opts(args) {
        Err(ConfigError::HelpRequested(opts)) => {
            print_usage(&program, opts);
            return;
        }

        Err(e) => {
            println!("Error: {}", e);
            return;
        }

        Ok(cmd_config) => {
            let path =
                match cmd_config.config_file {
                    Some(ref cf) => Path::new(cf).to_path_buf(),
                    None =>
                        match cmd_config.workspace_dir {
                            Some(ref wd) =>
                                Path::new(&wd.clone()).join("peerington.toml"),
                            None => {
                                println!("the impossible has happened");
                                return;
                            }
                        }
                };
            match parse_config(&path) {
                Err(e) => {
                    println!("error reading config file: {}", e);
                    return;
                },
                Ok(file_config) => {
                    let config =
                        match merge_configs(&cmd_config, &file_config) {
                            Ok(c) => c,
                            Err(e) => {
                                println!("error merging configs: {}", e);
                                return
                            }
                        };
                    run(config);
                }
            }
        }
    }
}

fn run(config: Config) {
    println!("listening on:");
    for ref a in &config.listen_addresses {
        println!("  {}", a);
    }
    println!("configured seeds:");
    for ref a in &config.seed_addresses {
        println!("  {}", a);
    }
    println!("workspace: {}", config.workspace_dir);
    println!("node uuid: {}", config.uuid.hyphenated());
    
    let conf = Arc::new(config);
    match NodeState::new(conf.clone()) {
        Ok(node_state) => {
            let ns = Arc::new(node_state);
            let ns2 = ns.clone();
            let (sender, receiver) = sync_channel(100);
            thread::spawn(move || {
                loop {
                    let d = receiver.recv().unwrap();
                    match d {
                        Message::Hello(u, addrs) => {
                            println!("received hello from {}: {:?}", u, addrs);
                            match ns2.address_map.lock() {
                                Ok(mut addr_map) => {
                                    addr_map.insert(u, addrs);
                                }
                                Err(_) => {
                                    println!("cannot lock address map");
                                }
                            };
                        },
                        Message::Broadcast(msg) => {
                            println!("broadcast: {}", msg);
                        }
                    }
                }
            });
            start_listeners(ns.clone(), sender);
            connect_seeds(ns.clone());
            repl(conf, ns);
            ()
        },
        Err(e) =>
            println!("cannot create node state: {}", e)
    }
}

/// Peerington tool command.
enum Command {
    /// Quit the read-eval-print loop.
    Quit,
    /// Print statistics to the console.
    Stats,
    /// Print all known nodes.
    Nodes,
    /// Send a message to a specific node.
    Send(Uuid, String),
}

impl fmt::Display for Command {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Command::Quit =>
                write!(f, "quit"),
            Command::Stats =>
                write!(f, "stats"),
            Command::Nodes =>
                write!(f, "nodes"),
            Command::Send(ref u, ref s) =>
                write!(f, "send {} {}", u, s),
        }
    }
}

impl Command {
    fn parse(input: &str) -> Result<Command, CommandParseError> {
        let tokens: Vec<_> = input.split(' ').collect();
        if tokens.len() > 0 {
            match tokens[0] {
                "q" | "qu" | "qui" | "quit" =>
                    Ok(Command::Quit),
                "s" | "st" | "sta" | "stat" | "stats" =>
                    Ok(Command::Stats),
                "nodes" =>
                    Ok(Command::Nodes),
                "send" => {
                    if tokens.len() > 2 {
                        if let Ok(u) = Uuid::parse_str(tokens[1]) {
                            let msg = tokens[2];
                            Ok(Command::Send(u, msg.to_string()))
                        } else {
                            Err(CommandParseError::Syntax("send UUID MSG"))
                        }
                    } else {
                        Err(CommandParseError::Syntax("send UUID MSG"))
                    }
                },
                _ =>  {
                    Err(CommandParseError::UnknownCommand(tokens[0]))
                }
            }
        } else {
            Err(CommandParseError::Syntax("no command"))
        }
    }
}

/// Error produced when parsing a command fails.
enum CommandParseError<'a>  {
    UnknownCommand(&'a str),
    Syntax(&'a str),
}

impl <'a> fmt::Display for CommandParseError<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CommandParseError::UnknownCommand(s) =>
                write!(f, "unknown command: {}", s),
            CommandParseError::Syntax(s) =>
                write!(f, "invalid syntax: {}", s),
        }
    }
}

/// Read-eval-print loop of the peerington command.
fn repl(_config: Arc<Config>, node_state: Arc<NodeState>) {
    let prompt = b"peer> ";
    let mut input = String::new();
    
    loop {
        input.clear();
        if let Err(e) = io::stdout().write(prompt) {
            println!("cannot write prompt: {}", e);
            return;
        }
        if let Err(e) = io::stdout().flush() {
            println!("cannot write prompt: {}", e);
            return;
        }
        match io::stdin().read_line(&mut input) {
            Ok(_) => {
                match input.trim() {
                    "" =>
                        continue,
                    trimmed =>
                        match Command::parse(trimmed) { 
                            Err(e) =>
                                println!("Error: {}", e),
                            Ok(Command::Quit) => {
                                println!("[exiting]");
                                return;
                            }
                            Ok(cmd) =>
                                execute(cmd, node_state.clone())
                        }
                }
            }
            Err(error) =>
                println!("cannot read stdin: {}", error),
        }
    }
}

/// Execute a peerington command.
fn execute(cmd: Command, node_state: Arc<NodeState>) {
    match cmd {
        Command::Nodes => {
            println!("connected:");
            match node_state.connected_nodes_recv.lock() {
                Ok(connected_nodes) => {
                    for (name, node_info) in &*connected_nodes {
                        println!("  {}: {}", name, node_info.node_info.address);
                    }
                    ()
                }
                Err(_) => {
                    println!("cannot lock node map");
                }
            };
            match node_state.connected_nodes_send.lock() {
                Ok(connected_nodes) => {
                    for (name, node_info) in &*connected_nodes {
                        println!("  {}: {}", name, node_info.node_info.address);
                    }
                    ()
                }
                Err(_) => {
                    println!("cannot lock node map");
                }
            }
            println!("addresses:");
            match node_state.address_map.lock() {
                Ok(addr_map) => {
                    for (name, addr) in &*addr_map {
                        println!("  {}: {:?}", name, addr);
                    }
                    ()
                }
                Err(_) => {
                    println!("cannot lock node map");
                }
            }
        },
        Command::Send(uuid, msg) => {
            println!("sending...");
            send_message(node_state, &uuid, Message::Broadcast(msg));
            println!("sent.");
        },
        _ =>
            println!("You want me to {}?", cmd)
    };
}
