use std::{io::Write, net::SocketAddrV4};

use pnet::packet::{
    udp::{self, MutableUdpPacket, UdpPacket},
    Packet,
};

// constants
pub const UDP_HEADER_LEN: usize = 8;

pub fn wrap_udp(packet: Vec<u8>, source: &SocketAddrV4, dest: &SocketAddrV4) -> Vec<u8> {
    let length = packet.len() + UDP_HEADER_LEN;
    let mut buf = vec![0u8; length];
    let mut udp_packet = MutableUdpPacket::new(&mut buf).unwrap();
    udp_packet.set_destination(dest.port());
    udp_packet.set_source(source.port());
    udp_packet.set_length(length as u16);
    udp_packet.set_payload(&packet);
    udp_packet.set_checksum(udp::ipv4_checksum(
        &UdpPacket::new(udp_packet.packet()).unwrap(),
        &source.ip(),
        dest.ip(),
    ));

    udp_packet.packet().to_vec()
}

pub fn write_varint(writer: &mut impl Write, mut value: i32) {
    let mut buffer = [0];
    if value == 0 {
        writer.write_all(&buffer).unwrap();
    }
    while value != 0 {
        buffer[0] = (value & 0b0111_1111) as u8;
        value = (value >> 7) & (i32::max_value() >> 6);
        if value != 0 {
            buffer[0] |= 0b1000_0000;
        }
        writer.write_all(&buffer).unwrap();
    }
}
