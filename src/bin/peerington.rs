// Copyright 2016 Martin Grabmueller. See the LICENSE file at the
// top-level directory of this distribution for license information.
//

extern crate peerington;
extern crate env_logger;
extern crate uuid;

use peerington::config::get_config;
use peerington::config::print_usage;
use peerington::error::ConfigError;
use peerington::config::Config;
use peerington::node::NodeState;
use peerington::node::start_networking;
use peerington::node::send_message;
use peerington::message::Message;

use uuid::Uuid;

use std::sync::Arc;
use std::env;
use std::io;
use std::io::Write;
use std::fmt;

fn main() {
    env_logger::init().unwrap();

    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();


    match get_config(args) {
        Err(ConfigError::HelpRequested(opts)) => {
            print_usage(&program, opts);
        }

        Err(e) => {
            println!("Error: {}", e);
        }

        Ok(config) =>
            run(config)
    }
}

fn handler(msg: Message) {
    match msg {
        Message::Broadcast(msg) => {
            println!("broadcast: {}", msg);
        },
        _ => {
            println!("error: unknown message: {:?}", msg)
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
            start_networking(ns.clone(), handler);
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
