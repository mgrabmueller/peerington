// Copyright 2016 Martin Grabmueller. See the LICENSE file at the
// top-level directory of this distribution for license information.
//

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::collections::BTreeMap;
use std::io::Cursor;
use std::io::Read;
use std::io::Write;
use std::net::TcpListener;
use std::net::TcpStream;
use std::thread;

use std::sync::mpsc::SyncSender;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::sync_channel;

use openssl::ssl;
use openssl::nid;
use openssl::x509;
use openssl::x509::X509ValidationError::*;
use uuid::Uuid;

use super::message;
use super::config;
use super::error;
use super::node;

pub struct NodeInfo {
    pub uuid: Uuid,
    pub address: SocketAddr,
}

pub struct NodeInfoRecv {
    pub node_info: NodeInfo,
}

pub struct NodeInfoSend {
    pub node_info: NodeInfo,
    pub tx: SyncSender<message::Message>
}

pub struct NodeState {
    pub config: Arc<config::Config>,
    pub ssl_context: ssl::SslContext,
    pub address_map: Arc<Mutex<BTreeMap<Uuid, Vec<String>>>>,
    pub connected_nodes_recv: Arc<Mutex<BTreeMap<Uuid, NodeInfoRecv>>>,
    pub connected_nodes_send: Arc<Mutex<BTreeMap<Uuid, NodeInfoSend>>>,
}

impl NodeState {
    pub fn new(config: Arc<config::Config>) -> Result<NodeState, error::Error> {
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

        let addr_map = BTreeMap::new();
        let node_map_recv = BTreeMap::new();
        let node_map_send = BTreeMap::new();
        Ok(NodeState {
            config: config,
            ssl_context: ssl_context,
            address_map: Arc::new(Mutex::new(addr_map)),
            connected_nodes_recv: Arc::new(Mutex::new(node_map_recv)),
            connected_nodes_send: Arc::new(Mutex::new(node_map_send)),
        })
    }
}

pub fn find_addrs(node_state: Arc<NodeState>,
              to: &Uuid) -> Option<Vec<String>> {
    match node_state.address_map.lock() {
        Ok(addr_map) => {
            if let Some(addrs) = addr_map.get(&to) {
                Some(addrs.clone())
            } else {
                None
                }
        }
        Err(_) => {
            error!("cannot lock node map");
                None
        }
    }
}

pub fn find_tx(node_state: Arc<node::NodeState>,
           to: &Uuid) -> Option<SyncSender<message::Message>> {
    match node_state.connected_nodes_send.lock() {
        Ok(connected_nodes) => {
            if let Some(ni) = connected_nodes.get(&to) {
                Some(ni.tx.clone())
            } else {
                None
                }
        }
        Err(_) => {
            error!("cannot lock node map");
                None
        }
    }
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

pub fn send_message(node_state: Arc<node::NodeState>,
                    to: &Uuid,
                    message: message::Message) {
    let tx = node::find_tx(node_state.clone(), to);
    match tx {
        Some(tx) => {
            tx.send(message).expect(
                &format!("could not send internal message to {}", to))
        },
        None => {
            match node::find_addrs(node_state.clone(), to) {
                Some(addrs) => {
                    if addrs.len() > 0 {
                        let addr = &addrs[0];
                        connect_to_node(node_state.clone(), addr);
                        let tx = node::find_tx(node_state, to);
                        match tx {
                            Some(tx) => {
                                tx.send(message).expect(
                                    &format!("could not send internal message to {}", to))
                            },
                            None => {
                                error!("could not connect to node: {}", to);
                            }
                        }
                    }
                },
                None => {
                    error!("send to unknown node: {}", to);
                }
            }
        }
    }
}


fn recv_handler_loop(_node_state: Arc<node::NodeState>, _uuid: Uuid,
                     stream: &mut ssl::SslStream<TcpStream>, sender: SyncSender<message::Message>) {
    let mut buf = [33; 1024];
    let mut msg = Vec::new();
    loop {
        match stream.ssl_read(&mut buf) {
            Ok(0) =>
                break,
            Ok(n) => {
                //                io::stdout().write(&buf[0..n]).unwrap();
                msg.extend(&buf[0..n]);
                let mut c = Cursor::new(msg.clone());
                match message::Message::read(&mut c) {
                    Err(e) => {
                        error!("cannot parse message: {}", e);
                    },
                    Ok(m) => {
                        let pos = c.position();
                        let rest = msg.split_off(pos as usize);
                        msg = rest;
                        sender.send(m).unwrap();
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

/// This loop repeatedly takes messages from the given Receiver,
/// encodes them and sends them over the connection.
fn send_handler_loop(_node_state: Arc<node::NodeState>, stream: &mut ssl::SslStream<TcpStream>, rx: Receiver<message::Message>) {
    loop {
        match rx.recv() {
            Ok(msg) => {
                let buf = Vec::new();
                let mut c = Cursor::new(buf);
                match msg.write(&mut c) {
                    Ok(()) => {
                        let v = c.into_inner();
                        let n = v.len();
                        match stream.ssl_write(&v) {
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
                        error!("could not serialize message: {}", e);
                    }
                }
            },
            Err(e) => {
                error!("error receiving internal message: {}", e);
                break;
            }
        }
    }
}

/// Retrieve the UUID of a peer from an established TLS connection and
/// returns None if that is not possible.
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
fn recv_handler(node_state: Arc<node::NodeState>, stream: &mut ssl::SslStream<TcpStream>,
                sender: SyncSender<message::Message>) {
    if let Ok(peer) = stream.get_ref().peer_addr() {
        info!("connected to {}", peer);
        match get_peer_uuid(stream) {
            Some(u) => {
                info!("UUID of peer: {}", u);
                let inserted =
                    match node_state.connected_nodes_recv.lock() {
                        Ok(mut connected_nodes) => {
                            connected_nodes.insert(u,
                                                   node::NodeInfoRecv{
                                                       node_info:
                                                       node::NodeInfo{
                                                           uuid: u,
                                                           address: peer
                                                       }
                                                   });
                            true
                        }
                        Err(_) => {
                            error!("cannot lock node map");
                            false
                        }
                    };
                if inserted {
                    recv_handler_loop(node_state.clone(), u, stream, sender);
                    match node_state.connected_nodes_recv.lock() {
                        Ok(mut connected_nodes) => {
                            connected_nodes.remove(&u);
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

/// Handle an established TLS connection.  The UUID of the peer is
/// taken from the peer certificate.
fn send_handler(node_state: Arc<node::NodeState>,
                stream: &mut ssl::SslStream<TcpStream>,
                handshake: SyncSender<()>) {
    let peer = stream.get_ref().peer_addr().unwrap();
    info!("connected to {}", peer);
    match get_peer_uuid(stream) {
        None => {
            error!("cannot determine peer UUID");
        },
        Some(u) => {
            let (tx, rx) = sync_channel(100);
            info!("UUID of peer: {}", u);
            let inserted =
                match node_state.connected_nodes_send.lock() {
                    Ok(mut connected_nodes) => {
                        connected_nodes.insert(u,
                                               node::NodeInfoSend{
                                                   node_info:
                                                   node::NodeInfo{
                                                       uuid: u,
                                                       address: peer,
                                                   },
                                                   tx: tx.clone(),
                                               });
                        true
                    }
                    Err(_) => {
                        error!("cannot lock node map");
                        false
                    }
                };
            if inserted {
                match node_state.address_map.lock() {
                    Ok(mut addr_map) => {
                        addr_map.entry(u).or_insert(vec![]).push(peer.to_string());
                    }
                    Err(_) => {
                        error!("cannot lock address map");
                    }
                };

                tx.send(message::Message::Hello(node_state.config.uuid,
                                                node_state.config.listen_addresses.clone())).unwrap();

                handshake.send(()).unwrap();
                send_handler_loop(node_state.clone(), stream, rx);
                match node_state.connected_nodes_send.lock() {
                    Ok(mut connected_nodes) => {
                        connected_nodes.remove(&u);
                        ()
                    }
                    Err(_) => {
                        error!("cannot lock node map");
                    }
                }
                info!("{} disconnected", peer);
            }
        }
    }
}

/// Bind to the given address and wait for incoming connections, using
/// the context to establish TLS connections.  Call the handler
/// function for each connection.
fn listener(node_state: Arc<node::NodeState>, addr: String,
            sender: SyncSender<message::Message>) {
    match TcpListener::bind(addr.as_str()) {
        Ok(listener) => {
            info!("listening on {}", listener.local_addr().unwrap());
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        let ns = node_state.clone();
                        let a = addr.clone();
                        let send = sender.clone();
                        thread::spawn(move || {
                            match ssl::Ssl::new(&ns.ssl_context) {
                                Ok(ssl) => {
                                    match ssl::SslStream::accept(ssl, stream) {
                                        Ok(mut ssl_stream) => {
                                            recv_handler(ns, &mut ssl_stream, send);
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
fn connect_to_node(node_state: Arc<node::NodeState>, addr: &String) {
    match TcpStream::connect(addr.as_str()) {
        Err(e) => {
            error!("cannot connect to {}: {}", addr, e);
        },
        Ok(stream) => {
            match ssl::Ssl::new(&node_state.ssl_context) {
                Err(e) => {
                    error!("cannot create ssl context: {}", e);
                },
                Ok(ssl) => {
                    match ssl::SslStream::connect(ssl, stream) {
                        Err(e) => {
                            error!("cannot establish ssl connection: {}", e);
                        },
                        Ok(mut ssl_stream) => {
                            let (handshake_tx, handshake_rx) = sync_channel(0);
                            thread::spawn(move || {
                                send_handler(node_state, &mut ssl_stream, handshake_tx);
                            });
                            let () = handshake_rx.recv().unwrap();
                        }
                    }
                }
            }
        }
    }
}

fn start_listeners(node_state: Arc<node::NodeState>,
                       sender: SyncSender<message::Message>) {
    for addr in node_state.config.listen_addresses.clone() {
        let a = addr.clone();
        let ns = node_state.clone();
        let s = sender.clone();
        thread::spawn(move || listener(ns, a, s));
    }
}

fn connect_seeds(node_state: Arc<node::NodeState>) {
    for addr in node_state.config.seed_addresses.clone() {
        let a = addr.clone();
        let ns = node_state.clone();
        thread::spawn(move || connect_to_node(ns, &a));
    }
}

/// Kick off the networking subsystem. Creates listener threads for
/// all configured listener addresses and starts sending threads for
/// all configured seeds.  Additional connections will be created when
/// other peers are connected or messages are sent to unconnected but
/// known peers.
pub fn start_networking<Handler>(node_state: Arc<node::NodeState>,
                        handler: Handler)
    where Handler: Fn(message::Message) -> () + Send + 'static
{
    // Create a channel for receiving messages. All threads handling
    // incoming connections will send parsed messages to this channel.
    let (sender, receiver) = sync_channel(1000);
    
    start_listeners(node_state.clone(), sender);
    connect_seeds(node_state.clone());

    thread::spawn(move || {
        loop {
            let d = receiver.recv().unwrap();
            match d {
                message::Message::Hello(u, addrs) => {
                    info!("received hello from {}: {:?}", u, addrs);
                    match node_state.address_map.lock() {
                        Ok(mut addr_map) => {
                            addr_map.insert(u, addrs);
                        }
                        Err(_) => {
                            error!("cannot lock address map");
                        }
                    };
                },
                _ => {
                    handler(d);
                }
            }
        }
    });
}
