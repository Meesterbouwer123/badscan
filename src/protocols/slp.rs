use byteorder::{BigEndian, WriteBytesExt};

use crate::utils;

use super::TcpProtocol;

pub struct MinecraftSlpProtocol {
    hello_packet: Vec<u8>,
}

impl MinecraftSlpProtocol {
    pub fn new() -> Self {
        Self {
            hello_packet: generate_hello_packet("test", 3, 47),
        }
    }
}

impl TcpProtocol for MinecraftSlpProtocol {
    fn initial_packet(&self, _dest: &std::net::SocketAddrV4) -> Option<Vec<u8>> {
        Some(self.hello_packet.clone())
    }

    fn name(&self) -> String {
        "SLP".to_string()
    }

    fn default_port(&self) -> u16 {
        25565
    }
}

fn generate_hello_packet(hostname: &str, port: u16, protocol: i32) -> Vec<u8> {
    let mut packets: Vec<Vec<u8>> = vec![];

    // make handshake packet
    let mut handshake_packet = vec![
        0x00, // 0x00 = handshake packet
    ];
    utils::write_varint(&mut handshake_packet, protocol); // protocol
    utils::write_varint(&mut handshake_packet, hostname.len() as i32); // hostname len
    handshake_packet.extend_from_slice(hostname.as_bytes()); // hostname
    handshake_packet.write_u16::<BigEndian>(port).unwrap(); // port
    utils::write_varint(&mut handshake_packet, 1); // next state = status (1)

    packets.push(handshake_packet);

    let status_request_packet = vec![0x00];
    packets.push(status_request_packet);

    let mut full_packet = vec![];
    for packet in packets {
        utils::write_varint(&mut full_packet, packet.len() as i32);
        full_packet.extend_from_slice(&packet);
    }

    full_packet
}
