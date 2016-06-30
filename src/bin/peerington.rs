// Copyright 2016 Martin Grabmueller. See the LICENSE file at the
// top-level directory of this distribution for license information.
//

extern crate peerington;
extern crate env_logger;
extern crate uuid;

use std::sync::atomic::AtomicUsize;

use peerington::config::get_config;
use peerington::config::print_usage;
use peerington::error::ConfigError;
use peerington::config::Config;
use peerington::node::NodeState;
use peerington::node::PeerState;
use peerington::node::Availability;
use peerington::node::start_networking;
use peerington::node::send_message;
use peerington::node::get_election_state;
use peerington::node::current_leader;
use peerington::message::Message;

use uuid::Uuid;

use std::sync::atomic::Ordering;
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
    /// Print node state
    State,
    /// Print all known nodes.
    Nodes,
    /// Send a message to a specific node.
    Send(Uuid, String),
    /// Show configuration.
    Config,
    /// Show information on all known peers.
    Peers,
}

impl fmt::Display for Command {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Command::Quit =>
                write!(f, "quit"),
            Command::State =>
                write!(f, "state"),
            Command::Nodes =>
                write!(f, "nodes"),
            Command::Send(ref u, ref s) =>
                write!(f, "send {} {}", u, s),
            Command::Config =>
                write!(f, "config"),
            Command::Peers =>
                write!(f, "peers"),
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
                "s" | "st" | "sta" | "stat" | "state" =>
                    Ok(Command::State),
                "nodes" =>
                    Ok(Command::Nodes),
                "config" =>
                    Ok(Command::Config),
                "p" | "pe" | "pee" | "peer" | "peers" =>
                    Ok(Command::Peers),
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
            println!("addresses:");
            match node_state.address_map.read() {
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
        Command::Config => {
            let config = &node_state.config;
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
            },
        Command::Peers => {
            match node_state.peers.lock() {
                Ok(peers) => {
                    println!("uuid                                      rcv   snd    re    se    ce state");
                    let self_peer_state =
                        PeerState{uuid: node_state.config.uuid,
                                  recv_conns: AtomicUsize::new(0),
                                  send_conns: AtomicUsize::new(0),
                                  send_errors: AtomicUsize::new(0),
                                  recv_errors: AtomicUsize::new(0),
                                  connect_errors: AtomicUsize::new(0),
                                  send_channel: None,
                                  availability: Availability::Up};
                    let mut ps = Vec::new();
                    for (name, peer_state) in &*peers {
                        ps.push((name, peer_state));
                    }

                    ps.push((&node_state.config.uuid,
                             &self_peer_state));
                    ps.sort_by(|&(a, _), &(b, _)| a.cmp(&b));

                    for (name, peer_state) in ps {
                        let marker1 = if *name == self_peer_state.uuid {
                            "*" } else { " " };
                        
                        let marker2 = if Some(*name) == current_leader(node_state.clone()) {
                            "L" } else { " " };
                        
                        println!("{}{} {} {:5} {:5} {:5} {:5} {:5} {:5?}",
                                 marker1,
                                 marker2,
                                 name,
                                 peer_state.recv_conns.load(Ordering::Relaxed),
                                 peer_state.send_conns.load(Ordering::Relaxed),
                                 peer_state.recv_errors.load(Ordering::Relaxed),
                                 peer_state.send_errors.load(Ordering::Relaxed),
                                 peer_state.connect_errors.load(Ordering::Relaxed),
                                 peer_state.availability,
                        );
                    }
                    ()
                }
                Err(_) => {
                    println!("cannot lock node map");
                }
            }
        },
        Command::State => {
            let (leadership, election_state) = get_election_state(node_state);
            println!("leadership: {:?}, elections state: {:?}", leadership, election_state)
            
        }
        Command::Quit => {
            // Should be handled in caller.
            unreachable!();
        }
    };
}
