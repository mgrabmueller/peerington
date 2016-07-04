// Copyright 2016 Martin Grabmueller. See the LICENSE file at the
// top-level directory of this distribution for license information.
//

extern crate peerington;
extern crate env_logger;
extern crate uuid;
extern crate term;

use peerington::config::get_config;
use peerington::config::print_usage;
use peerington::error::ConfigError;
use peerington::config::Config;
use peerington::node::NodeState;
use peerington::node::PeerState;
use peerington::node::Availability;
use peerington::node::Leadership;
use peerington::node::ElectionState;
use peerington::node::start_networking;
use peerington::node::send_message;
use peerington::node::get_election_state;
use peerington::node::current_leader;
use peerington::message::Message;

use uuid::Uuid;

use std::sync::atomic::Ordering;
use std::sync::atomic::AtomicUsize;
use std::collections::HashSet;
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
    /// Give some help on the REPL.
    Help,
    /// Print node state
    State,
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
            Command::Help =>
                write!(f, "help"),
            Command::State =>
                write!(f, "state"),
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
                "q" | "quit" =>
                    Ok(Command::Quit),
                "h" | "help" =>
                    Ok(Command::Help),
                "s" | "state" =>
                    Ok(Command::State),
                "c" | "config" =>
                    Ok(Command::Config),
                "p" | "peers" =>
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
fn repl(config: Arc<Config>, node_state: Arc<NodeState>) {
    let prompt = config.uuid.hyphenated().to_string();
    let mut input = String::new();
    
    loop {
        input.clear();
        if let Err(e) = io::stdout().write(&prompt.as_bytes()[..8]) {
            println!("cannot write prompt: {}", e);
            return;
        }
        if let Err(e) = io::stdout().write(b"> ") {
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
        Command::Help => {
            println!("  help              display this help message");
            println!("  quit              terminate this node");
            println!("  send UUID MSG     send the text MSG to node UUID");
            println!("  peers             display the node ring");
            println!("  config            display the node configuration");
            println!("  state             display the state of this node");
        },
        Command::Send(uuid, msg) => {
            println!("sending...");
            send_message(node_state, &uuid, Message::Broadcast(msg));
            println!("sent.");
        },
        Command::Config => {
            let config = &node_state.config;
            println!("uuid: {}", config.uuid.hyphenated());
            println!("listening on:");
            for ref a in &config.listen_addresses {
                println!("  {}", a);
            }
            println!("configured seeds:");
            for ref a in &config.seed_addresses {
                println!("  {}", a);
            }
            println!("workspace: {}", config.workspace_dir);
            },
        Command::Peers => {
            match node_state.peers.lock() {
                Ok(peers) => {
                    println!(" # SL uuid                                   rcv   snd    ce state   listen");
                    let mut self_addrs = HashSet::new();
                    for a in &node_state.config.listen_addresses {
                        self_addrs.insert(a.clone());
                    }
                    let self_peer_state =
                        PeerState{uuid: node_state.config.uuid,
                                  recv_conns: AtomicUsize::new(0),
                                  send_conns: AtomicUsize::new(0),
                                  connect_errors: AtomicUsize::new(0),
                                  send_channel: None,
                                  availability: Some(Availability::Up),
                                  addresses: self_addrs};
                    let mut ps = Vec::new();
                    for (name, peer_state) in &*peers {
                        ps.push((name, peer_state));
                    }

                    ps.push((&node_state.config.uuid,
                             &self_peer_state));
                    ps.sort_by(|&(a, _), &(b, _)| a.cmp(&b));

                    let mut t = term::stdout().unwrap();

                    for (idx, &(name, peer_state)) in ps.iter().enumerate() {
                        let is_self = *name == self_peer_state.uuid;
                        let is_leader = Some(*name) == current_leader(node_state.clone());

                        if is_self {
                            t.fg(term::color::GREEN).unwrap();
                        } 
                        if is_leader {
                            t.attr(term::Attr::Standout(true)).unwrap();
                        } 
                        println!("{:2} {}{} {} {:5} {:5} {:5} {:7} {:?}",
                                 idx,
                                 if is_self { "*" } else { " " },
                                 if is_leader { "L" } else { " " },
                                 name,
                                 peer_state.recv_conns.load(Ordering::Relaxed),
                                 peer_state.send_conns.load(Ordering::Relaxed),
                                 peer_state.connect_errors.load(Ordering::Relaxed),
                                 match peer_state.availability {
                                     None => "unknown",
                                     Some(Availability::Up) => "up",
                                     Some(Availability::Down) => "down",
                                 },
                                 peer_state.addresses
                        );
                     t.reset().unwrap();
                    }
                    ()
                }
                Err(_) => {
                    println!("cannot lock node map");
                }
            }
        },
        Command::State => {
            let (leadership, election_state) = get_election_state(node_state.clone());
            println!("uuid:   {}", node_state.config.uuid);
            println!("leader: {} {}",
                     match leadership {
                         Leadership::SelfLeader => format!("{}", node_state.config.uuid),
                         Leadership::LeaderKnown(u) => format!("{}", u),
                         Leadership::LeaderUnknown => "unknown".to_string(),
                     },
                     match election_state {
                         ElectionState::Participant => "(election in progress)",
                         ElectionState::NonParticipant => "",
                     });
        }
        Command::Quit => {
            // Should be handled in caller.
            unreachable!();
        }
    };
}
