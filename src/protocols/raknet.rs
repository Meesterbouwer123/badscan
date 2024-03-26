use std::io::{self, Cursor, Read};

use byteorder::{BigEndian, ReadBytesExt};

use crate::{
    scanner::StatelessProtocol,
    utils::{self, cookie},
};

const MAGIC: [u8; 16] = [
    0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe, 0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78,
];

#[derive(Debug, Clone)]
pub struct RaknetProtocol {}

impl RaknetProtocol {
    pub fn new() -> Self
    where
        Self: Send + Sync + Sized,
    {
        Self {}
    }
}

impl StatelessProtocol for RaknetProtocol {
    fn initial_packet(&self, addr: &std::net::SocketAddrV4) -> Vec<u8> {
        let cookie = utils::cookie(addr);
        let mut packet = vec![];
        packet.extend_from_slice(&[0x01]); // packet ID
        packet.extend_from_slice(&cookie.to_be_bytes()); // for some reason the server sends our timestamp back lol
        packet.extend_from_slice(&cookie.to_be_bytes()); // we will 100% abuse this to contain our cookie
        packet.extend_from_slice(&MAGIC); // magic
        packet.extend_from_slice(&[0u8; 8]); // GUID

        packet
    }

    fn handle_packet(
        &self,
        _send_back: &dyn Fn(Vec<u8>),
        source: &std::net::SocketAddrV4,
        packet: &[u8],
    ) {
        // remember, we can't use .unwrap() here since then possible attackers could crash our scanner
        let cookie = cookie(source);

        // size check
        // 1 (packet ID) + 8 (timestamp) + 8 (server GUID) + MAGIC + 2 (short to the string) = 19
        if packet.len() <= 19 + MAGIC.len() {
            return;
        }

        let mut stream = Cursor::new(packet);

        // packet ID
        let Ok(packet_id) = stream.read_u8() else {
            return;
        };
        if packet_id != 0x1c {
            return;
        }

        // client timestamp, we store the cookie here
        let Ok(timestamp) = stream.read_u64::<BigEndian>() else {
            return;
        };

        if (timestamp & u32::MAX as u64) as u32 != cookie
            || ((timestamp >> 32) & u32::MAX as u64) as u32 != cookie
        // fun fact: the >> operation shifts by bits, not bytes
        {
            println!(
                "wrong cookie!, expected 2x {cookie:X}, got {:X} and {:X}",
                timestamp & u32::MAX as u64,
                (timestamp >> 32) & u32::MAX as u64
            );
            return;
        }

        // server GUID
        let Ok(guid) = stream.read_u64::<BigEndian>() else {
            return;
        };

        // magic
        let Ok(magic) = read_bytes(&mut stream, MAGIC.len()) else {
            return;
        };
        if magic != MAGIC {
            println!("bad magic");
            return;
        }

        // server id
        let Ok(server_id_len) = stream.read_u16::<BigEndian>() else {
            return;
        };

        let Ok(server_id) = read_bytes(&mut stream, server_id_len as usize) else {
            return;
        };

        if let Ok(server_id) = String::from_utf8(server_id) {
            println!("{guid:?} - {server_id}")
        }
    }

    fn name(&self) -> String {
        "Raknet".to_string()
    }
}

fn read_bytes(stream: &mut (dyn Read), length: usize) -> io::Result<Vec<u8>> {
    let mut bytes = vec![];
    for _ in 0..length {
        let mut buf = [0];
        stream.read(&mut buf)?;
        bytes.push(buf[0]);
    }

    Ok(bytes)
}
