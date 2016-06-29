// Copyright 2016 Martin Grabmueller. See the LICENSE file at the
// top-level directory of this distribution for license information.
//

use std::io::Read;
use std::io::Write;
use std::u16;

use uuid::Uuid;
use byteorder::BigEndian;
use byteorder::ReadBytesExt;
use byteorder::WriteBytesExt;

use super::error;

#[derive(Debug)]
pub enum Message {
    /// Message announcing the listening addresses of a node.  This is
    /// the first message sent when connecting to a listening node and
    /// may be sent again during the lifetime of a connection.
    Hello(Uuid, Vec<String>),
    Broadcast(String),
    Ping(Uuid),
    Pong(Uuid),
    Nodes(Vec<(Uuid, String)>),
    Election(Uuid),
    Elected(Uuid),
}

impl Message {
    pub fn read<R: Read>(r: &mut R) -> Result<Message, error::Error>  {
        let tag = try!(r.read_u8());
        match tag {
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

