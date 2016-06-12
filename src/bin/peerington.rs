extern crate peerington;
extern crate env_logger;

use peerington::parse_opts;
use peerington::print_usage;
use peerington::error::ConfigError;
use peerington::Config;
use peerington::NodeState;
use peerington::Message;
use peerington::start_listeners;
use peerington::connect_seeds;
use peerington::send_message;

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

        Ok(config) => {
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

            match NodeState::new(&config) {
                Ok(node_state) => {
                    let ns = Arc::new(node_state);
                    let (sender, receiver) = sync_channel(100);
                    thread::spawn(move || {
                        loop {
                            let d = receiver.recv().unwrap();
                            match d {
                                Message::Data(u, v) => {
                                    println!("received data from {}: {:?}", u, v);
                                }
                            }
                        }
                    });
                    start_listeners(&config, ns.clone(), sender);
                    connect_seeds(&config, ns.clone());
                    repl(&config, ns);
                    ()
                },
                Err(e) =>
                    println!("cannot create node state: {}", e)
            };
        }
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
    /// Broadcast a message.
    Send,
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
            Command::Send =>
                write!(f, "send"),
        }
    }
}

impl Command {
    fn parse(input: &str) -> Result<Command, CommandParseError> {
        match input {
            "q" | "qu" | "qui" | "quit" =>
                Ok(Command::Quit),
            "s" | "st" | "sta" | "stat" | "stats" =>
                Ok(Command::Stats),
            "nodes" =>
                Ok(Command::Nodes),
            "send" =>
                Ok(Command::Send),
            _ =>
                Err(CommandParseError::UnknownCommand(input))
        }
    }
}

/// Error produced when parsing a command fails.
enum CommandParseError<'a>  {
    UnknownCommand(&'a str)
}

impl <'a> fmt::Display for CommandParseError<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CommandParseError::UnknownCommand(s) =>
                write!(f, "unknown command: {}", s)
        }
    }
}

/// Read-eval-print loop of the peerington command.
fn repl(_config: &Config, node_state: Arc<NodeState>) {
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
                        println!("  {}: {}", name, addr);
                    }
                    ()
                }
                Err(_) => {
                    println!("cannot lock node map");
                }
            }
        },
        Command::Send => {
            let mut us = Vec::new();
            match node_state.connected_nodes_send.lock() {
                Ok(connected_nodes) => {
                    for (_, node_info) in &*connected_nodes {
                        us.push(node_info.node_info.uuid);
                    }
                    ()
                }
                Err(_) => {
                    println!("cannot lock node map");
                }
            }
            for u in us {
                send_message(node_state.clone(), &u,
                             Message::Data(u, vec![41, 41, 41]));
            }
        },
        _ =>
            println!("You want me to {}?", cmd)
    };
}
