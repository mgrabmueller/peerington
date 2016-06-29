// Copyright 2016 Martin Grabmueller. See the LICENSE file at the
// top-level directory of this distribution for license information.
//

extern crate rand;

use std::sync::Arc;
use std::sync::Mutex;
use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::io::Cursor;
use std::io::Read;
use std::io::Write;
use std::net::TcpListener;
use std::net::TcpStream;
use std::thread;

use std::sync::mpsc::SyncSender;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::sync_channel;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time;

use self::rand::Rng;

use openssl::ssl;
use openssl::nid;
use openssl::x509;
use openssl::x509::X509ValidationError::*;
use uuid::Uuid;

use super::message;
use super::config;
use super::error;
use super::node;

#[derive(Debug, Clone, Copy)]
pub enum Availability {
    Up,
    Down,
}

pub struct PeerState {
    pub uuid: Uuid,
    pub recv_conns: AtomicUsize,
    pub send_conns: AtomicUsize,
    pub send_channel: Option<SyncSender<message::Message>>,
    pub send_errors: AtomicUsize,
    pub recv_errors: AtomicUsize,
    pub connect_errors: AtomicUsize,
    pub availability: Availability,
}

pub enum ElectionState {
    NonParticipant,
    Participant,
    Elected,
}

pub struct NodeState {
    pub config: Arc<config::Config>,
    pub ssl_context: ssl::SslContext,
    pub address_map: Arc<Mutex<BTreeMap<Uuid, Vec<String>>>>,
    pub peers: Arc<Mutex<BTreeMap<Uuid, PeerState>>>,
    pub election_state: Mutex<ElectionState>,
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
        let peers = BTreeMap::new();
        Ok(NodeState {
            config: config,
            ssl_context: ssl_context,
            address_map: Arc::new(Mutex::new(addr_map)),
            peers: Arc::new(Mutex::new(peers)),
            election_state: Mutex::new(ElectionState::NonParticipant),
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

pub fn remove_send_channel(node_state: Arc<node::NodeState>,
                           to: &Uuid) {
    let mut peers = node_state.peers.lock().unwrap();
    match peers.entry(to.clone()) {
        Entry::Occupied(mut oe) => {
            oe.get_mut().send_channel = None;
        },
        Entry::Vacant(_) => {
            error!("cannot remove send channel for {}, does not exist", to);
        }
    }
}

pub fn find_send_channel(node_state: Arc<node::NodeState>,
               to: &Uuid) -> Option<SyncSender<message::Message>> {
    let peers = node_state.peers.lock().unwrap();
    if let Some(ps) = peers.get(&to) {
        match ps.send_channel {
            Some(ref c) => Some(c.clone()),
            None => None
        }
    } else {
        None
    }
    // match node_state.connected_nodes_send.lock() {
    //     Ok(connected_nodes) => {
    //         if let Some(ni) = connected_nodes.get(&to) {
    //             Some(ni.tx.clone())
    //         } else {
    //             None
    //             }
    //     }
    //     Err(_) => {
    //         error!("cannot lock node map");
    //             None
    //     }
    // }
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
//    trace!("sending to {}: {:?}", to, message);
    let tx = node::find_send_channel(node_state.clone(), to);
    match tx {
        Some(tx) => {
            match tx.send(message) {
                Ok(()) =>
                    (),
                Err(e) => {
                    error!("could not send internal message to {}: {}", to, e);
                    remove_send_channel(node_state, to);
                }
            };
        },
        None => {
            match node::find_addrs(node_state.clone(), to) {
                Some(addrs) => {
                    if addrs.len() > 0 {
                        let addr = &addrs[0];
                        let connected = connect_to_node(node_state.clone(), addr);
                        if connected {
                            {
                                let mut peers = node_state.peers.lock().unwrap();
                                let mut peer = peers.get_mut(&to).unwrap();
                                peer.connect_errors.store(0, Ordering::Relaxed);
                                peer.availability = Availability::Up;
                            }
                            let tx = node::find_send_channel(node_state, to);
                            match tx {
                                Some(tx) => {
                                    tx.send(message).expect(
                                        &format!("could not send internal message to {}", to))
                                },
                                None => {
                                    error!("could not connect to node: {}", to);
                                }
                            }
                        } else {
                            {
                                let mut peers = node_state.peers.lock().unwrap();
                                let mut peer = peers.get_mut(&to).unwrap();
                                peer.connect_errors.fetch_add(1, Ordering::Relaxed);
                                peer.availability = Availability::Down;
                            }
                        }
                    } else {
                        error!("no address known for node: {}", to);
                    }
                },
                None => {
                    error!("send to unknown node: {}", to);
                }
            }
        }
    }
}


fn recv_handler_loop(node_state: Arc<node::NodeState>, uuid: &Uuid,
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
                {
                    let peers = node_state.peers.lock().unwrap();
                    peers.get(&uuid).unwrap().recv_errors.store(0, Ordering::Relaxed);
                }
            },
            Err(e) => {
                error!("error when reading: {}", e);
                {
                    let peers = node_state.peers.lock().unwrap();
                    peers.get(&uuid).unwrap().recv_errors.fetch_add(1, Ordering::Relaxed);
                }
                break;
            }
        }
    }
}

/// This loop repeatedly takes messages from the given Receiver,
/// encodes them and sends them over the connection.
fn send_handler_loop(node_state: Arc<node::NodeState>,
                     uuid: &Uuid,
                     stream: &mut ssl::SslStream<TcpStream>,
                     rx: Receiver<message::Message>) {
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
                            Ok(x) => {
                                if x != n {
                                    error!("could not write everything");
                                    {
                                        let peers = node_state.peers.lock().unwrap();
                                        peers.get(&uuid).unwrap().send_errors.fetch_add(1, Ordering::Relaxed);
                                    }
                                    return;
                                }
                                {
                                    let peers = node_state.peers.lock().unwrap();
                                    peers.get(&uuid).unwrap().send_errors.store(0, Ordering::Relaxed);
                                }
                            },
                            Err(e) => {
                                error!("error when writing: {}", e);
                                {
                                    let peers = node_state.peers.lock().unwrap();
                                    peers.get(&uuid).unwrap().send_errors.fetch_add(1, Ordering::Relaxed);
                                }
                                return;
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
                return;
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
                {
                    let mut peers = node_state.peers.lock().unwrap();
                    peers.entry(u).or_insert_with(|| PeerState{uuid: u,
                                                               recv_conns: AtomicUsize::new(0),
                                                               send_conns: AtomicUsize::new(0),
                                                               send_errors: AtomicUsize::new(0),
                                                               recv_errors: AtomicUsize::new(0),
                                                               connect_errors: AtomicUsize::new(0),
                                                               send_channel: None,
                                                               availability: Availability::Up})
                        .recv_conns.fetch_add(1, Ordering::Relaxed);
                }
                
                recv_handler_loop(node_state.clone(), &u, stream, sender);
                
                {
                    let peers = node_state.peers.lock().unwrap();
                    peers.get(&u).unwrap().recv_conns.fetch_sub(1, Ordering::Relaxed);
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

            // Make sure the send_handler_loop receives the Hello
            // message before any other message. We do this by sending
            // before entering the sending part of the channel into
            // the global map.
            tx.send(message::Message::Hello(node_state.config.uuid,
                                            node_state.config.listen_addresses.clone())).unwrap();
            

            {
                let mut peers = node_state.peers.lock().unwrap();
                let ps = peers.entry(u).or_insert_with(|| PeerState{uuid: u,
                                                                    recv_conns: AtomicUsize::new(0),
                                                                    send_conns: AtomicUsize::new(0),
                                                                    send_errors: AtomicUsize::new(0),
                                                                    recv_errors: AtomicUsize::new(0),
                                                                    connect_errors: AtomicUsize::new(0),
                                                                    send_channel: None,
                                                                    availability: Availability::Up});
                ps.send_conns.fetch_add(1, Ordering::Relaxed);
                ps.send_channel = Some(tx);
            }
            {
                let mut addr_map = node_state.address_map.lock().unwrap();
                addr_map.entry(u).or_insert(vec![]).push(peer.to_string());
            }
            
            handshake.send(()).unwrap();
            
            send_handler_loop(node_state.clone(), &u, stream, rx);
            
            {
                let peers = node_state.peers.lock().unwrap();
                peers.get(&u).unwrap().send_conns.fetch_sub(1, Ordering::Relaxed);
            }
            info!("{} disconnected", peer);
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
fn connect_to_node(node_state: Arc<node::NodeState>, addr: &String) -> bool {
    trace!("connecting to {}", addr);
    match TcpStream::connect(addr.as_str()) {
        Err(e) => {
            error!("cannot connect to {}: {}", addr, e);
            false
        },
        Ok(stream) => {
            match ssl::Ssl::new(&node_state.ssl_context) {
                Err(e) => {
                    error!("cannot create ssl context: {}", e);
                    false
                },
                Ok(ssl) => {
                    match ssl::SslStream::connect(ssl, stream) {
                        Err(e) => {
                            error!("cannot establish ssl connection: {}", e);
                            false
                        },
                        Ok(mut ssl_stream) => {
                            let (handshake_tx, handshake_rx) = sync_channel(0);
                            thread::spawn(move || {
                                send_handler(node_state, &mut ssl_stream, handshake_tx);
                            });
                            let () = handshake_rx.recv().unwrap();
                            true
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

fn msg_recv_loop<Handler>(node_state: Arc<node::NodeState>,
                      handler: Handler,
                      receiver: Receiver<message::Message>)
    where Handler: Fn(message::Message) -> () + Send + 'static
{
    let self_uuid = node_state.config.uuid;
    loop {
        let d = receiver.recv().unwrap();
//        trace!("msg_recv_loop: {:?}", d);
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
            message::Message::Ping(u) => {
                let ns = node_state.clone();
                send_message(ns, &u, message::Message::Pong(self_uuid));
            },
            message::Message::Pong(_u) => {
                // Do nothing for now.
            },
            message::Message::Nodes(uuids) => {
//                info!("received node list: {:?}", uuids);
                {
                    let mut addr_map = node_state.address_map.lock().unwrap();
                    for (u, addr) in uuids {
                        if u != self_uuid {
                            let _e = addr_map.entry(u).or_insert_with(|| vec![addr]);
                        }
                    }
                }
            },
            _ => {
                handler(d);
            }
        }
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

    let node_state_clone  = node_state.clone();
    thread::spawn(move || {
        msg_recv_loop(node_state.clone(), handler, receiver);
    });
    thread::spawn(move || {
        chatter_loop(node_state_clone);
    });
}

/// Return a list of all known UUIDs plus listen address.
fn get_peer_uuids_and_addresses(node_state: Arc<NodeState>) -> Vec<(Uuid, String)> {
    let mut ret = Vec::new();
    let peers = node_state.address_map.lock().unwrap();
    for (u, p) in peers.iter() {
        if p.len() > 0 {
            ret.push((u.clone(), p[0].clone()));
        }
    }
    ret
}

/// 
fn chatter_loop(node_state: Arc<NodeState>) {
    const ITERATION_SLEEP_MS: u64 = 2000;
    let mut rng = rand::thread_rng();

    let self_uuid = node_state.config.uuid;
    loop {
//        trace!("chatter_loop");
        thread::sleep(time::Duration::from_millis(ITERATION_SLEEP_MS));
        {
            let uuids = get_peer_uuids_and_addresses(node_state.clone());
            for &(u, _) in &uuids {
                {
//                    trace!("considering {}", u);
                    let availability = {
                        let peers = node_state.peers.lock().unwrap();
                        peers.get(&u).map(|peer| peer.availability)
                    };
                    match availability {
                        None => {
                            if rng.gen::<u8>() % 10 <= 5 {
                                send_message(node_state.clone(), &u,
                                             message::Message::Ping(self_uuid))
                            }
                        },
                        Some(Availability::Up) => {
                                if rng.gen::<u8>() % 10 <= 3 {
                                let mut us: Vec<(Uuid, String)> = uuids.clone()
                                    .into_iter()
                                    .filter(|&(uu,_)| uu != u)
                                    .collect();
                                us.push((self_uuid,
                                         node_state.config.listen_addresses[0].clone()));
                                send_message(node_state.clone(), &u,
                                             message::Message::Nodes(us))
                            } else {
                                send_message(node_state.clone(), &u,
                                             message::Message::Ping(self_uuid))
                            }
                        },
                        Some(Availability::Down) => {
                            if rng.gen::<u8>() % 10 <= 5 {
                                send_message(node_state.clone(), &u,
                                             message::Message::Ping(self_uuid))
                            }
                        }
                    }
                    
                }
            }
        }            
    }
}
