use std::net::{Ipv4Addr, SocketAddrV4};

use pnet::packet::{udp::{self, MutableUdpPacket, UdpPacket}, Packet};


// constants
pub const UDP_HEADER_LEN: usize = 8;

pub fn wrap_udp(packet: Vec<u8>, source_ip: &Ipv4Addr, dest: &SocketAddrV4) -> Vec<u8> {
    let length = packet.len() + UDP_HEADER_LEN;
    let mut buf = vec![0u8; length];
    let mut udp_packet = MutableUdpPacket::new(&mut buf).unwrap();
    udp_packet.set_destination(dest.port());
    udp_packet.set_source(61000);
    udp_packet.set_length(length as u16);
    udp_packet.set_payload(&packet);
    udp_packet.set_checksum(udp::ipv4_checksum(
        &UdpPacket::new(udp_packet.packet()).unwrap(),
        &source_ip,
        dest.ip(),
    ));

    udp_packet.packet().to_vec()
}