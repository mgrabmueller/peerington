// Copyright 2016 Martin Grabmueller. See the LICENSE file at the
// top-level directory of this distribution for license information.
//

use std::io::Read;
use std::io::Write;
use std::fmt;
use std::u16;

use uuid::Uuid;
use byteorder::BigEndian;
use byteorder::ReadBytesExt;
use byteorder::WriteBytesExt;

use super::error;
use super::node;

/// Maximum supported inter-node protocol version that this version of
/// the library supports.
pub const MAX_SUPPORTED_VERSION: Version = Version(1);

/// Minimum supported inter-node protocol version that this version of
/// the library supports.
pub const MIN_SUPPORTED_VERSION: Version = Version(1);

/// Newtype wrapper for a protocol version number.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(pub u16);

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Version(v) => write!(f, "{}", v),
        }
    }
}

impl Version {
    pub fn number(&self) -> u16 {
        match *self {
            Version(v) => v
        }
    }
}

/// Newtype wrapper for a membership token.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Token(pub u64);

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Token(v) => write!(f, "{}", v),
        }
    }
}

impl Token {
    pub fn number(&self) -> u64 {
        match *self {
            Token(v) => v
        }
    }
}

/// Message type for inter-node communications.
#[derive(Debug)]
pub enum Message {
    /// Message for establishing the inter-node protocol.  This is the
    /// first message on establishing a connection and is sent by the
    /// connecting node.  It contains the highest version that the
    /// connecting node supports.
    Handshake(Version, Version),
    /// This is the response to a handshake message. It contains two
    /// versions: the first is the version the accepting peer is
    /// offering, and the second is the maximum version supported by
    /// the accepting node.
    HandshakeAck(Version, Version),
    /// This is the failure response to a handshake message. It
    /// contains the minimum and maximum supported protocol version.
    /// the accepting node.
    HandshakeNak(Version, Version),
    /// Message announcing the listening addresses of a node.  This is
    /// the first message sent when connecting to a listening node and
    /// may be sent again during the lifetime of a connection.
    Hello(Uuid, Vec<String>),
    /// A simple text transmission message, used for debugging.
    Broadcast(String),
    /// A periodic heartbeat message.  The included UUID is the id of
    /// the sender.
    Ping(Uuid),
    /// Response to the `Ping` message.  The included UUID is the id
    /// of the sender.
    Pong(Uuid),
    /// Node information message. This is sent on connection
    /// establishment (both by the connecting and the accepting node)
    /// and periodically.  It contains a list of all nodes known to
    /// the sending node.  Each entry is a tuple of the known node's
    /// UUID and one listening address.
    Nodes(Vec<(Uuid, String)>),
    /// Node membership information.  This is only sent from a leader
    /// and is discarded when received from a non-leader.
    Members(Uuid, Vec<(Uuid, node::Membership)>),
    /// Request to join the ring.
    Join(Uuid, Token),
    /// Accepting a join request.
    JoinAck(Uuid, Token),
    /// Request to leave the ring.
    Leave(Uuid, Token),
    /// Accepting a leave request.
    LeaveAck(Uuid, Token),
    /// Election message. To start an election, a node sends this
    /// message to the next one in the node ring.  The included UUID
    /// is the current leader suggestion.
    Election(Uuid),
    /// Elected message.  As soon as the the previous election phase
    /// has selected a leader, this message announcing the UUID of the
    /// new leader is sent around the ring.
    Elected(Uuid),
}

impl Message {
    pub fn read<R: Read>(r: &mut R) -> Result<Message, error::Error>  {
        let tag = try!(r.read_u8());
        match tag {
            1 => {
                let version_offered_min = try!(r.read_u16::<BigEndian>());
                let version_offered_max = try!(r.read_u16::<BigEndian>());
                Ok(Message::Handshake(Version(version_offered_min), Version(version_offered_max)))
            },
            2 => {
                let version_agreed = try!(r.read_u16::<BigEndian>());
                let version_supported = try!(r.read_u16::<BigEndian>());
                Ok(Message::HandshakeAck(Version(version_agreed), Version(version_supported)))
            },
            3 => {
                let version_min = try!(r.read_u16::<BigEndian>());
                let version_max = try!(r.read_u16::<BigEndian>());
                Ok(Message::HandshakeNak(Version(version_min), Version(version_max)))
            },
            10 => {
                let mut buf = [0; 16];
                try!(r.read_exact(&mut buf));
                let uuid = try!(Uuid::from_bytes(&buf));
                let addr_count = try!(r.read_u16::<BigEndian>());
                let mut addrs = Vec::new();
                for _ in 0..addr_count {
                    let addr_len = try!(r.read_u16::<BigEndian>());
                    let mut v = vec![0; addr_len as usize];
                    try!(r.read_exact(&mut v));
                    let addr = try!(String::from_utf8(v));
                    addrs.push(addr);
                }
                Ok(Message::Hello(uuid, addrs))
            },
            20 => {
                let msg_len = try!(r.read_u16::<BigEndian>());
                let mut v = vec![0; msg_len as usize];
                try!(r.read_exact(&mut v));
                let msg = try!(String::from_utf8(v));
                Ok(Message::Broadcast(msg))
            },
            30 => {
                let mut buf = [0; 16];
                try!(r.read_exact(&mut buf));
                let uuid = try!(Uuid::from_bytes(&buf));
                Ok(Message::Ping(uuid))
            },
            40 => {
                let mut buf = [0; 16];
                try!(r.read_exact(&mut buf));
                let uuid = try!(Uuid::from_bytes(&buf));
                Ok(Message::Pong(uuid))
            },
            50 => {
                let uuid_count = try!(r.read_u16::<BigEndian>());
                let mut uuids = Vec::new();
                for _ in 0..uuid_count {
                    let mut buf = [0; 16];
                    try!(r.read_exact(&mut buf));
                    let uuid = try!(Uuid::from_bytes(&buf));
                    let addr_len = try!(r.read_u16::<BigEndian>());
                    let mut v = vec![0; addr_len as usize];
                    try!(r.read_exact(&mut v));
                    let addr = try!(String::from_utf8(v));
                    uuids.push((uuid, addr));
                }
                Ok(Message::Nodes(uuids))
            },
            51 => {
                let mut buf = [0; 16];
                try!(r.read_exact(&mut buf));
                let from_uuid = try!(Uuid::from_bytes(&buf));

                let uuid_count = try!(r.read_u16::<BigEndian>());
                let mut members = Vec::new();
                for _ in 0..uuid_count {
                    try!(r.read_exact(&mut buf));
                    let uuid = try!(Uuid::from_bytes(&buf));
                    let membership = match try!(r.read_u8()) {
                        0 => node::Membership::Unknown,
                        1 => node::Membership::Joining,
                        2 => node::Membership::Member,
                        3 => node::Membership::Leaving,
                        _ => return Err(error::Error::MessageParse("invalid membership tag")),
                    };
                    members.push((uuid, membership));
                }
                Ok(Message::Members(from_uuid, members))
            },
            52 => {
                let mut buf = [0; 16];
                try!(r.read_exact(&mut buf));
                let from_uuid = try!(Uuid::from_bytes(&buf));
                let token = try!(r.read_u64::<BigEndian>());
                Ok(Message::Join(from_uuid, Token(token)))
            },
            53 => {
                let mut buf = [0; 16];
                try!(r.read_exact(&mut buf));
                let from_uuid = try!(Uuid::from_bytes(&buf));
                let token = try!(r.read_u64::<BigEndian>());
                Ok(Message::JoinAck(from_uuid, Token(token)))
            },
            54 => {
                let mut buf = [0; 16];
                try!(r.read_exact(&mut buf));
                let from_uuid = try!(Uuid::from_bytes(&buf));
                let token = try!(r.read_u64::<BigEndian>());
                Ok(Message::Leave(from_uuid, Token(token)))
            },
            55 => {
                let mut buf = [0; 16];
                try!(r.read_exact(&mut buf));
                let from_uuid = try!(Uuid::from_bytes(&buf));
                let token = try!(r.read_u64::<BigEndian>());
                Ok(Message::LeaveAck(from_uuid, Token(token)))
            },
            60 => {
                let mut buf = [0; 16];
                try!(r.read_exact(&mut buf));
                let uuid = try!(Uuid::from_bytes(&buf));
                Ok(Message::Election(uuid))
            },
            61 => {
                let mut buf = [0; 16];
                try!(r.read_exact(&mut buf));
                let uuid = try!(Uuid::from_bytes(&buf));
                Ok(Message::Elected(uuid))
            },
            _ => {
                Err(error::Error::MessageParse("invalid message tag"))
            }
        }
    }

    pub fn write<W: Write>(&self, w: &mut W) -> Result<(), error::Error> {
        match *self {
            Message::Handshake(Version(version_offered_min), Version(version_offered_max)) => {
                try!(w.write_u8(1));
                try!(w.write_u16::<BigEndian>(version_offered_min));
                try!(w.write_u16::<BigEndian>(version_offered_max));
                Ok(())
            },
            Message::HandshakeAck(Version(version_agreed), Version(version_supported)) => {
                try!(w.write_u8(2));
                try!(w.write_u16::<BigEndian>(version_agreed));
                try!(w.write_u16::<BigEndian>(version_supported));
                Ok(())
            },
            Message::HandshakeNak(Version(version_min), Version(version_max)) => {
                try!(w.write_u8(3));
                try!(w.write_u16::<BigEndian>(version_min));
                try!(w.write_u16::<BigEndian>(version_max));
                Ok(())
            },
            Message::Hello(uuid, ref addrs) => {
                try!(w.write_u8(10));

                let buf = uuid.as_bytes();
                try!(w.write(buf));
                assert!(addrs.len() <= (u16::MAX as usize));
                try!(w.write_u16::<BigEndian>(addrs.len() as u16));
                for i in 0..addrs.len() {
                    assert!(addrs[i].len() <= (u16::MAX as usize));
                    try!(w.write_u16::<BigEndian>(addrs[i].len() as u16));
                    try!(w.write(addrs[i].as_bytes()));
                }
                Ok(())
            },
            Message::Broadcast(ref msg) => {
                try!(w.write_u8(20));
                assert!(msg.len() <= (u16::MAX as usize));
                try!(w.write_u16::<BigEndian>(msg.len() as u16));
                try!(w.write(msg.as_bytes()));
                Ok(())
            },
            Message::Ping(uuid) => {
                try!(w.write_u8(30));
                let buf = uuid.as_bytes();
                try!(w.write(buf));
                Ok(())
            },
            Message::Pong(uuid) => {
                try!(w.write_u8(40));
                let buf = uuid.as_bytes();
                try!(w.write(buf));
                Ok(())
            },
            Message::Nodes(ref uuids) => {
                try!(w.write_u8(50));

                assert!(uuids.len() <= (u16::MAX as usize));
                try!(w.write_u16::<BigEndian>(uuids.len() as u16));
                for i in 0..uuids.len() {
                    let (ref uuid, ref addr) = uuids[i];
                    let buf = uuid.as_bytes();
                    try!(w.write(buf));
                    assert!(addr.len() <= (u16::MAX as usize));
                    try!(w.write_u16::<BigEndian>(addr.len() as u16));
                    try!(w.write(addr.as_bytes()));
                }
                Ok(())
            },
            Message::Members(ref from_uuid, ref members) => {
                try!(w.write_u8(51));

                let buf = from_uuid.as_bytes();
                try!(w.write(buf));

                assert!(members.len() <= (u16::MAX as usize));
                try!(w.write_u16::<BigEndian>(members.len() as u16));
                for i in 0..members.len() {
                    let (ref uuid, membership) = members[i];
                    let buf = uuid.as_bytes();
                    try!(w.write(buf));
                    let tag =
                        match membership {
                            node::Membership::Unknown => 0,
                            node::Membership::Joining => 1,
                            node::Membership::Member  => 2,
                            node::Membership::Leaving => 3,
                        };
                    try!(w.write_u8(tag));
                }
                Ok(())
            },
            Message::Join(ref from_uuid, ref token) => {
                try!(w.write_u8(52));

                let buf = from_uuid.as_bytes();
                try!(w.write(buf));
                try!(w.write_u64::<BigEndian>(token.number()));
                Ok(())
            },
            Message::JoinAck(ref from_uuid, ref token) => {
                try!(w.write_u8(53));

                let buf = from_uuid.as_bytes();
                try!(w.write(buf));
                try!(w.write_u64::<BigEndian>(token.number()));
                Ok(())
            },
            Message::Leave(ref from_uuid, ref token) => {
                try!(w.write_u8(54));

                let buf = from_uuid.as_bytes();
                try!(w.write(buf));
                try!(w.write_u64::<BigEndian>(token.number()));
                Ok(())
            },
            Message::LeaveAck(ref from_uuid, ref token) => {
                try!(w.write_u8(55));

                let buf = from_uuid.as_bytes();
                try!(w.write(buf));
                try!(w.write_u64::<BigEndian>(token.number()));
                Ok(())
            },
            Message::Election(uuid) => {
                try!(w.write_u8(60));

                let buf = uuid.as_bytes();
                try!(w.write(buf));
                Ok(())
            },
            Message::Elected(uuid) => {
                try!(w.write_u8(61));

                let buf = uuid.as_bytes();
                try!(w.write(buf));
                Ok(())
            },
        }
    }
}
