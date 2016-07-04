// Copyright 2016 Martin Grabmueller. See the LICENSE file at the
// top-level directory of this distribution for license information.
//

extern crate rand;

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::RwLock;
use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::collections::HashSet;
use std::io::Cursor;
use std::io::Read;
use std::io::Write;
use std::net::TcpListener;
use std::net::TcpStream;
use std::thread;
use std::cmp;

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

/// Defines whether a node is considered up (available) or down
/// (unavailable).  A node is marked as down when it is not possible
/// to connect to the node's listen address.  Note that availability
/// can only be a guess, since failures can happen at any time in a
/// distributed network and it might take a while to detect it.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Availability {
    /// Node is available right now.
    Up,

    /// Node is not available right now.
    Down,
}

/// Records information about a node that was connected at least once
/// or whose UUID has been communicated in the current run of the
/// current node.
pub struct PeerState {
    /// UUID of the peer.
    pub uuid: Uuid,

    /// Protocol version used for sending messages to this peer, if
    /// known.
    pub proto_version_send: Option<message::Version>,

    /// Protocol version used for receiving messages from this peer,
    /// if known.
    pub proto_version_recv: Option<message::Version>,

    /// Number of active receive connections.
    pub recv_conns: AtomicUsize,

    /// Number of active send connections.
    pub send_conns: AtomicUsize,

    /// Internal channel for sending messages to the node.
    pub send_channel: Option<SyncSender<message::Message>>,

    /// Number of connection errors that have been detected.
    pub connect_errors: AtomicUsize,

    /// Currently known availability of the node.
    pub availability: Option<Availability>,

    /// Public listen addresses of the node.
    pub addresses: HashSet<String>,
}

/// Whether the current node currently participates in an election
/// (`Participant`) or not (`NonParticipant`).
#[derive(Clone, Copy, Debug)]
pub enum ElectionState {
    /// Not participating in an election right now.
    NonParticipant,

    /// Participating in an election.
    Participant,
}

/// Current knowledge about cluster leadership (or coordinator).  All
/// nodes start with `LeaderUnknown`, which will trigger a leader
/// election.  The state is set to `LeaderUnknown` whenever the
/// current leader is recognized as `Down` or when an election message
/// is received.
#[derive(Clone, Copy, Debug)]
pub enum Leadership {
    /// Nothing known about cluster leadership.
    LeaderUnknown,

    /// Leader is known and has the given UUID. Invariant: the UUID
    /// can never be the one of the current node.
    LeaderKnown(Uuid),

    /// The current node is the leader.
    SelfLeader,
}

/// State of the current node.
pub struct NodeState {
    /// Node configuration.
    pub config: Arc<config::Config>,

    /// Context for establishing TLS connections. Contains
    /// certificates, keys, TLS settings etc.
    pub ssl_context: ssl::SslContext,

    /// Detailed information about peers that have been connected at
    /// least once since the current run of the current node.
    pub peers: Mutex<BTreeMap<Uuid, PeerState>>,

    /// State about ongoing leadership exceptions.
    pub election_state: RwLock<(Leadership, ElectionState)>,
}

impl NodeState {
    /// Create a new node state based on the given configuration.
    pub fn new(config: Arc<config::Config>) -> Result<NodeState, error::Error> {
        let mut ssl_context = try!(ssl::SslContext::new(ssl::SslMethod::Tlsv1));

        let mut ca_path = config.workspace_dir.clone();
        ca_path.push_str("/ca-chain.cert.pem");

        try!(ssl_context.set_CA_file(&ca_path));

        let mut cert_path = config.workspace_dir.clone();
        cert_path.push_str("/");
        cert_path.push_str(&config.uuid.to_string());
        cert_path.push_str(".cert.pem");

        try!(ssl_context.set_certificate_file(&cert_path, x509::X509FileType::PEM));

        let mut priv_key_path = config.workspace_dir.clone();
        priv_key_path.push_str("/");
        priv_key_path.push_str(&config.uuid.to_string());
        priv_key_path.push_str(".key.pem");

        try!(ssl_context.set_private_key_file(&priv_key_path,
                                              x509::X509FileType::PEM));
        try!(ssl_context.check_private_key());

        ssl_context.set_verify(ssl::SSL_VERIFY_PEER
                               | ssl::SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                               Some(verify_client_cert));

        let peers = BTreeMap::new();
        Ok(NodeState {
            config: config,
            ssl_context: ssl_context,
            peers: Mutex::new(peers),
            election_state: RwLock::new((Leadership::LeaderUnknown,
                                         ElectionState::NonParticipant)),
        })
    }
}

/// Find the listen addresses of the node with the given UUID.
pub fn find_addrs(node_state: Arc<NodeState>,
                  to: &Uuid) -> Option<HashSet<String>> {
    let peers = node_state.peers.lock().unwrap();
    peers.get(&to).map(|p| p.addresses.clone())
}

/// Delete the send channel for the node with the given UUID. This is
/// necessary when a send connection is disconnected.
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

/// Get the current active send channel for the node with the given
/// UUID.
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
}

/// TLS client certificate verification hook.  Just returns true if
/// OpenSSL's verification succeeded, otherwise try to print a useful
/// error message.
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

/// Attempt to send a message to the node with the given UUID.
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
                    if let Some(ref addr) = addrs.iter().next() {
                        let connected = connect_to_node(node_state.clone(), addr);
                        if connected {
                            {
                                let mut peers = node_state.peers.lock().unwrap();
                                let mut peer = peers.get_mut(&to).unwrap();
                                peer.connect_errors.store(0, Ordering::Relaxed);
                                peer.availability = Some(Availability::Up);
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
                                match peers.get_mut(&to) {
                                    Some(peer) => {
                                        peer.connect_errors.fetch_add(1, Ordering::Relaxed);
                                        peer.availability = Some(Availability::Down);
                                    },
                                    None => {}
                                }
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

fn read_message(stream: &mut ssl::SslStream<TcpStream>,
                buffer: &mut Vec<u8>) -> Result<(message::Message, Vec<u8>), error::Error> {
    let mut buf = [0; 1024];
    let n = try!(stream.ssl_read(&mut buf));

    buffer.extend(&buf[0..n]);
    let mut c = Cursor::new(buffer.clone());
    let message = try!(message::Message::read(&mut c));
    let pos = c.position();
    let rest = buffer.split_off(pos as usize);
    Ok((message, rest))
}

fn read_handshake(stream: &mut ssl::SslStream<TcpStream>) ->
    Result<(message::Version, message::Version, Vec<u8>), error::Error>
{
    let mut msg = Vec::new();
    let message = try!(read_message(stream, &mut msg));
    match message {
        (message::Message::Handshake(version_offered_min, version_offered_max), rest) =>
            Ok((version_offered_min, version_offered_max, rest)),
        _ =>
            Err(error::Error::Other("unexpected message in protocol negotiation"))
    }
}

fn write_message(stream: &mut ssl::SslStream<TcpStream>, msg: message::Message) -> Result<(), error::Error> {
    let buf = Vec::new();
    let mut c = Cursor::new(buf);
    try!(msg.write(&mut c));
    let v = c.into_inner();
    let n = v.len();
    let x = try!(stream.ssl_write(&v));
    if x != n {
        Err(error::Error::Other("could not write everything"))
    } else {
        Ok(())
    }
}

fn recv_negotiate_version(stream: &mut ssl::SslStream<TcpStream>) -> Result<(message::Version, Vec<u8>), error::Error> {
    let (version_offered_min, version_offered_max, rest) = try!(read_handshake(stream));

    if version_offered_min > message::MAX_SUPPORTED_VERSION {
        error!("version in connection attempt unsupported (too high), closing connection");
        try!(write_message(stream, message::Message::HandshakeNak(message::MIN_SUPPORTED_VERSION,
                                                                   message::MAX_SUPPORTED_VERSION)));
        Err(error::Error::Other("connecting version not supported (too high)"))
    } else if version_offered_max < message::MIN_SUPPORTED_VERSION {
        try!(write_message(stream, message::Message::HandshakeNak(message::MIN_SUPPORTED_VERSION,
                                                                   message::MAX_SUPPORTED_VERSION)));
        Err(error::Error::Other("connecting version not supported (too low)"))
    } else {
        let version_agreed = cmp::max(cmp::max(version_offered_min, message::MIN_SUPPORTED_VERSION),
                                      cmp::min(version_offered_max, message::MAX_SUPPORTED_VERSION));
        try!(write_message(stream, message::Message::HandshakeAck(version_agreed,
                                                                  message::MAX_SUPPORTED_VERSION)));
        Ok((version_agreed, rest))
    }
}

fn send_negotiate_version(stream: &mut ssl::SslStream<TcpStream>) ->
    Result<(message::Version, message::Version, Vec<u8>), error::Error>
{
    try!(write_message(stream, message::Message::Handshake(message::MIN_SUPPORTED_VERSION, message::MAX_SUPPORTED_VERSION)));
    let mut msg = Vec::new();
    let message = try!(read_message(stream, &mut msg));
    match message {
        (message::Message::HandshakeAck(version_agreed, version_max), rest) => {
            Ok((version_agreed, version_max, rest))
        },
        (message::Message::HandshakeNak(version_min, version_max), _rest) => {
            return Err(error::Error::ProtocolVersion(version_min, version_max))
        },
        _ => {
            Err(error::Error::Other("unexpected message in protocol negotiation"))
        }
    }
}

/// Loop reading data from a connected node, decoding messages and
/// forwarding them to the given channel.
fn recv_handler_loop(stream: &mut ssl::SslStream<TcpStream>,
                     msg: &mut Vec<u8>,
                     _proto_version: message::Version,
                     sender: SyncSender<message::Message>) {
    loop {
        match read_message(stream, msg) {
            Ok((message, rest)) => {
                *msg = rest;
                sender.send(message).unwrap();
            },
            Err(e) => {
                error!("error when reading: {}", e);
                return;
            }
        }
    }
}

/// This loop repeatedly takes messages from the given Receiver,
/// encodes them and sends them over the connection.
fn send_handler_loop(stream: &mut ssl::SslStream<TcpStream>,
                     _proto_version: message::Version,
                     rx: Receiver<message::Message>) {
    loop {
        match rx.recv() {
            Ok(msg) => {
                match write_message(stream, msg) {
                    Ok(()) => {},
                    Err(e) => {
                        error!("cannot write message: {}", e);
                        return;
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
        info!("connection from {}", peer);
        match get_peer_uuid(stream) {
            Some(u) => {
                info!("{} connected", u);

                let (proto_version, mut msg) =
                    match recv_negotiate_version(stream) {
                        Ok(rest) => rest,
                        Err(e) => {
                            error!("cannot establish incoming connection: {}", e);
                            return;
                        }
                    };

                // When a previously unknown peer UUID is encountered
                // that might become a new leader, we forget our
                // current leader so that a new election will take
                // place.
                if let Some(cur_leader) = current_leader(node_state.clone()) {
                    if !is_known_uuid(node_state.clone(), &u) && u > cur_leader {
                        trace!("previously unknown leader candidate connected, forgetting leader");
                        forget_leader(node_state.clone());
                    }
                }

                {
                    let mut peers = node_state.peers.lock().unwrap();
                    let mut pe = peers.entry(u)
                        .or_insert_with(|| PeerState{uuid: u,
                                                     proto_version_send: None,
                                                     proto_version_recv: None,
                                                     recv_conns: AtomicUsize::new(0),
                                                     send_conns: AtomicUsize::new(0),
                                                     connect_errors: AtomicUsize::new(0),
                                                     send_channel: None,
                                                     availability: Some(Availability::Up),
                                                     addresses: HashSet::new()});
                    pe.recv_conns.fetch_add(1, Ordering::Relaxed);
                    pe.proto_version_recv = Some(proto_version);
                }

                recv_handler_loop(stream, &mut msg, proto_version, sender);

                if let Some(cur_leader) = current_leader(node_state.clone()) {
                    if cur_leader == u {
                        forget_leader(node_state.clone());
                    }
                }
                {
                    let peers = node_state.peers.lock().unwrap();
                    peers.get(&u).unwrap().recv_conns.fetch_sub(1, Ordering::Relaxed);
                }
                info!("{} disconnected", u);
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
            info!("{} connected", u);

            let (proto_version, _proto_version_max, _msg) =
                match send_negotiate_version(stream) {
                    Ok(rest) => rest,
                    Err(e) => {
                        error!("cannot establish incoming connection: {}", e);
                        return;
                    }
                };

            // When a previously unknown peer UUID is encountered
            // that might become a new leader, we forget our
            // current leader so that a new election will take
            // place.
            if let Some(cur_leader) = current_leader(node_state.clone()) {
                if !is_known_uuid(node_state.clone(), &u) && u > cur_leader {
                    trace!("connected to previously unknown leader candidate, forgetting leader");
                    forget_leader(node_state.clone());
                }
            }

            // Make sure the send_handler_loop receives the Hello
            // message before any other message. We do this by sending
            // before entering the sending part of the channel into
            // the global map.
            tx.send(message::Message::Hello(node_state.config.uuid,
                                            node_state.config
                                            .listen_addresses.clone())).unwrap();

            // Also, send a node message if we know about the ring.
            let uuids = get_peer_uuids_and_addresses(node_state.clone());
            if uuids.len() > 0 {
                let node_msg = make_node_message(node_state.clone(), &uuids, &u, &node_state.config.uuid);
                tx.send(node_msg).unwrap();
            }

            {
                let mut peers = node_state.peers.lock().unwrap();
                let ps = peers.entry(u)
                    .or_insert_with(|| PeerState{uuid: u,
                                                 proto_version_send: None,
                                                 proto_version_recv: None,
                                                 recv_conns: AtomicUsize::new(0),
                                                 send_conns: AtomicUsize::new(0),
                                                 connect_errors: AtomicUsize::new(0),
                                                 send_channel: None,
                                                 availability: Some(Availability::Up),
                                                 addresses: HashSet::new()});
                ps.send_conns.fetch_add(1, Ordering::Relaxed);
                ps.proto_version_send = Some(proto_version);
                ps.send_channel = Some(tx);
                ps.addresses.insert(peer.to_string());
            }

            handshake.send(()).unwrap();

            send_handler_loop(stream, proto_version, rx);

            if let Some(cur_leader) = current_leader(node_state.clone()) {
                if cur_leader == u {
                    forget_leader(node_state.clone());
                }
            }
            {
                let peers = node_state.peers.lock().unwrap();
                peers.get(&u).unwrap().send_conns.fetch_sub(1, Ordering::Relaxed);
            }
            info!("{} connected", u);
        }
    }
    info!("{} disconnected", peer);
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

/// Start the listening threads for all configured listen addresses.
fn start_listeners(node_state: Arc<node::NodeState>,
                   sender: SyncSender<message::Message>) {
    for addr in node_state.config.listen_addresses.clone() {
        let a = addr.clone();
        let ns = node_state.clone();
        let s = sender.clone();
        thread::spawn(move || listener(ns, a, s));
    }
}

/// Attempt connections to all configured seed node listen addresses.
fn connect_seeds(node_state: Arc<node::NodeState>) {
    for addr in node_state.config.seed_addresses.clone() {
        let a = addr.clone();
        let ns = node_state.clone();
        thread::spawn(move || connect_to_node(ns, &a));
    }
}

fn make_node_message(node_state: Arc<NodeState>,
                     uuids: &Vec<(Uuid, String)>,
                     dest_uuid: &Uuid,
                     self_uuid: &Uuid) -> message::Message {
    let mut us: Vec<(Uuid, String)> = uuids.clone()
        .into_iter()
        .filter(|&(uu,_)| uu != *dest_uuid)
        .collect();
    us.push((*self_uuid,
             node_state.config.listen_addresses[0].clone()));
    message::Message::Nodes(us)
}
/// All incoming messages are handled in this loop. Messages for
/// cluster and peer handling are handled directly by modifying the
/// node states, other messages are passed to the given handler.
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
                //                info!("received hello from {}: {:?}", u, addrs);
                {
                    let mut  peers = node_state.peers.lock().unwrap();
                    peers.get_mut(&u).map(|p|
                                         for a in addrs {
                                             p.addresses.insert(a);
                                         });
                }
                let uuids = get_peer_uuids_and_addresses(node_state.clone());
                let node_msg = make_node_message(node_state.clone(), &uuids, &u, &self_uuid);
                send_message(node_state.clone(), &u, node_msg)
            },
            message::Message::Ping(u) => {
                let ns = node_state.clone();
                send_message(ns, &u, message::Message::Pong(self_uuid));
            },
            message::Message::Pong(_u) => {
                // Do nothing for now.
            },
            message::Message::Nodes(uuids) => {
                let known_uuids = get_known_uuids(node_state.clone());
                let cur_leader_mb = current_leader(node_state.clone());

                for (u, addr) in uuids {
                    if u != self_uuid {
                        let mut peers = node_state.peers.lock().unwrap();
                        peers.entry(u)
                            .or_insert_with(|| PeerState{uuid: u,
                                                         proto_version_send: None,
                                                         proto_version_recv: None,
                                                         recv_conns: AtomicUsize::new(0),
                                                         send_conns: AtomicUsize::new(0),
                                                         connect_errors: AtomicUsize::new(0),
                                                         send_channel: None,
                                                         availability: None,
                                                         addresses: HashSet::new()})
                            .addresses.insert(addr);
                    }

                    // When a previously unknown peer UUID is encountered
                    // that might become a new leader, we forget our
                    // current leader so that a new election will take
                    // place.
                    if let Some(cur_leader) = cur_leader_mb {
                        if !known_uuids.contains(&u) && u > cur_leader {
                            trace!("learned about previously unknown leader candidate, forgetting leader");
                            forget_leader(node_state.clone());
                        }
                    }
                }
            },

            message::Message::Election(proposed_uuid) => {
                let (_leadership, election_state) = get_election_state(node_state.clone());
                if let Some(next_uuid) = get_next_uuid(node_state.clone(),
                                                       &self_uuid) {
                    if proposed_uuid > self_uuid {
                        // trace!("forwarding election to {}, proposed UUID greater than mine",
                        //        next_uuid);
                        set_election_state(node_state.clone(),
                                           Leadership::LeaderUnknown,
                                           ElectionState::Participant);
                        send_message(node_state.clone(), &next_uuid,
                                     message::Message::Election(proposed_uuid));
                    } else if proposed_uuid < self_uuid {
                        match election_state {
                            ElectionState::NonParticipant => {
                                // trace!("forwarding election to {}, proposed UUID {} smaller than mine",
                                //        next_uuid, proposed_uuid);
                                set_election_state(node_state.clone(),
                                                   Leadership::LeaderUnknown,
                                                   ElectionState::Participant);
                                send_message(node_state.clone(), &next_uuid,
                                             message::Message::Election(self_uuid));
                            },
                            ElectionState::Participant => {
                                // trace!("already participant, dropping");
                            }
                        }
                    } else /* proposed_uuid == self_uuid */ {
                        match election_state {
                            ElectionState::NonParticipant => {
                                error!("got election message with own UUID, but not participant - dropping");
                            },
                            ElectionState::Participant => {
                                // trace!("got election msg for myself, turning to leader, sending Elected({}) to {}",
                                //        self_uuid, next_uuid);
                                set_election_state(node_state.clone(),
                                                   Leadership::LeaderUnknown,
                                                   ElectionState::NonParticipant);
                                send_message(node_state.clone(), &next_uuid,
                                             message::Message::Elected(self_uuid));
                            }
                        }
                    }
                } else {
                    error!("cannot determine next node in ring");
                }
            },

            message::Message::Elected(elected_uuid) => {
                // trace!("rcvd Elected({})", elected_uuid);
                let (_leadership, _) = get_election_state(node_state.clone());
                if let Some(next_uuid) = get_next_uuid(node_state.clone(),
                                                       &self_uuid) {
                    if self_uuid == elected_uuid {
                        // trace!("got elected msg for myself, becoming leader, stopping election");
                        info!("got elected as new leader");
                        set_election_state(node_state.clone(), Leadership::SelfLeader,
                                           ElectionState::NonParticipant);
                    } else {
                        // trace!("got elected msg for other node, recording as leader");
                        info!("new leader elected: {}", elected_uuid);
                        set_election_state(node_state.clone(),
                                           Leadership::LeaderKnown(elected_uuid),
                                           ElectionState::NonParticipant);
                        send_message(node_state.clone(), &next_uuid,
                                     message::Message::Elected(elected_uuid));
                    }
                } else {
                    error!("cannot determine next node in ring");
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

fn peer_availability(node_state: Arc<NodeState>, uuid: &Uuid) -> Option<Availability> {
    let peers = node_state.peers.lock().unwrap();
    peers.get(&uuid).and_then(|peer| peer.availability)
}

/// Return a list of all known UUIDs plus listen address.
fn get_peer_uuids_and_addresses(node_state: Arc<NodeState>) -> Vec<(Uuid, String)> {
    let mut ret = Vec::new();
    let peers = node_state.peers.lock().unwrap();
    for (u, p) in peers.iter() {
        if let Some(pp) = p.addresses.iter().next() {
            ret.push((u.clone(), pp.clone()));
        }
    }
    ret
}

fn forget_leader(node_state: Arc<NodeState>) {
    let mut es = node_state.election_state.write().unwrap();
    *es = (Leadership::LeaderUnknown, ElectionState::NonParticipant);
}

pub fn current_leader(node_state: Arc<NodeState>) -> Option<Uuid> {
    let es = node_state.election_state.read().unwrap();
    match *es {
        (Leadership::SelfLeader, _) => Some(node_state.config.uuid),
        (Leadership::LeaderKnown(u), _) => Some(u),
        (_, _) => None,
    }
}

fn is_known_uuid(node_state: Arc<NodeState>, uuid: &Uuid) -> bool {
    let peers = node_state.peers.lock().unwrap();
    for (u, _) in peers.iter() {
        if u == uuid {
            return true;
        }
    }
    return false;
}

fn get_known_uuids(node_state: Arc<NodeState>) -> HashSet<Uuid> {
    let peers = node_state.peers.lock().unwrap();
    let mut ret = HashSet::new();
    for (u, _) in peers.iter() {
        ret.insert(u.clone());
    }
    ret
}

/// Return the next UUID in the ring of all known UUIDs.
fn get_next_uuid(node_state: Arc<NodeState>,
                 from_uuid: &Uuid) -> Option<Uuid> {
    let mut uuids: Vec<_> = get_peer_uuids_and_addresses(node_state.clone())
        .into_iter()
        .map(|(u, _)| u)
        .filter(|u| peer_availability(node_state.clone(), &u) != Some(Availability::Down))
        .collect();
    if uuids.len() > 0 {
        uuids.sort_by(|&a, &b| a.cmp(&b));
        let next_uuid =
            match uuids
            .iter()
            .skip_while(|&a| a < from_uuid)
            .next() {
                None => uuids[0].clone(),
                Some(u) => u.clone(),
            };
        Some(next_uuid)
    } else {
        None
    }
}

fn set_election_state(node_state: Arc<NodeState>,
                      leadership: Leadership,
                      election_state: ElectionState) {
    let mut es = node_state.election_state.write().unwrap();
    *es = (leadership, election_state);
}

pub fn get_election_state(node_state: Arc<NodeState>) -> (Leadership, ElectionState) {
    let es = node_state.election_state.read().unwrap();
    *es
}

fn chatter_loop(node_state: Arc<NodeState>) {
    const ITERATION_SLEEP_MS: u64 = 2000;
    let mut rng = rand::thread_rng();

    let mut election_counter = 0;

    let self_uuid = node_state.config.uuid;
    loop {
        thread::sleep(time::Duration::from_millis(ITERATION_SLEEP_MS));
        let mut uuids = get_peer_uuids_and_addresses(node_state.clone());

        if uuids.len() > 0 {
            let es = get_election_state(node_state.clone());

            match es {
                (Leadership::LeaderUnknown, ElectionState::NonParticipant) => {
                    if let Some(next_uuid) = get_next_uuid(node_state.clone(),
                                                           &self_uuid) {
                        info!("leadership unknown, initiating election");
                        set_election_state(node_state.clone(),
                                           Leadership::LeaderUnknown,
                                           ElectionState::Participant);
                        send_message(node_state.clone(), &next_uuid,
                                     message::Message::Election(self_uuid));
                    }
                },
                (Leadership::LeaderKnown(ldr_uuid), ElectionState::NonParticipant) => {
                    if ldr_uuid < self_uuid {
                        if let Some(next_uuid) = get_next_uuid(node_state.clone(),
                                                               &self_uuid) {
                            info!("detected invalid leader, initiating election");
                            set_election_state(node_state.clone(),
                                               Leadership::LeaderUnknown,
                                               ElectionState::Participant);
                            send_message(node_state.clone(), &next_uuid,
                                         message::Message::Election(self_uuid));
                        }
                    }
                },
                (_, ElectionState::Participant) => {
                    election_counter += 1;
                    if election_counter > 3 {
                        info!("too long in election phase, restarting election process");
                        forget_leader(node_state.clone());
                        election_counter = 0;
                    }
                },
                _ => {
                }

            }
        }

        rng.shuffle(uuids.as_mut_slice());
        for &(u, _) in uuids.iter().take(2) {
            let availability = {
                let peers = node_state.peers.lock().unwrap();
                peers.get(&u).and_then(|peer| peer.availability)
            };
            match availability {
                None => {
                    if rng.gen::<u8>() % 100 < 10 {
                        send_message(node_state.clone(), &u,
                                     message::Message::Ping(self_uuid))
                    }
                },
                Some(Availability::Up) => {
                    if rng.gen::<u8>() % 100 < 10 {
                        let node_msg = make_node_message(node_state.clone(), &uuids, &u, &self_uuid);
                        send_message(node_state.clone(), &u, node_msg)
                    } else {
                        send_message(node_state.clone(), &u,
                                     message::Message::Ping(self_uuid))
                    }
                },
                Some(Availability::Down) => {
                    let conn_err_cnt  = {
                        let peers = node_state.peers.lock().unwrap();
                        peers.get(&u).map(|peer| peer.connect_errors.load(Ordering::Relaxed)).unwrap_or(0)
                    };
                    let prob = cmp::max(1, 100 / cmp::min(100, 2usize.pow(cmp::min(10, conn_err_cnt) as u32)));
                    if rng.gen::<usize>() % 100 <= prob {
                        send_message(node_state.clone(), &u,
                                     message::Message::Ping(self_uuid))
                    }
                }
            }
        }
    }
}
