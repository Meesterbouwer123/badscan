use std::net::SocketAddrV4;

use pnet::packet::{
    tcp::{self, MutableTcpPacket, TcpOption, TcpOptionPacket, TcpPacket},
    Packet,
};

#[derive(Debug, Clone, Default)]
pub struct TcpTemplate {
    tcp_len: usize,
    packet: Vec<u8>,
}

impl TcpTemplate {
    pub fn new(flags: u8, window: u16, options: Vec<TcpOption>) -> Self {
        let options_length_bytes: usize = options.iter().map(TcpOptionPacket::packet_size).sum();
        let options_length_words: usize = (options_length_bytes + 3) / 4;
        let tcp_len = 20 + options_length_words * 4;
        let mut buf = vec![0u8; tcp_len];
        let mut packet = MutableTcpPacket::new(&mut buf).unwrap();

        // add fields to the packet
        // first the default fields, these should be cached when possible
        packet.set_data_offset(5 + options_length_words as u8); // real offset is this * 4
        packet.set_reserved(0); // "must be zero" field, what should we put here :thinking:
        packet.set_flags(flags);
        packet.set_window(window);
        packet.set_urgent_ptr(0); //TODO: we should also be able to customize this
        packet.set_options(&options); // TCP options

        Self {
            tcp_len,
            packet: packet.packet().to_vec(),
        }
    }

    pub fn create(
        &self,
        source: &SocketAddrV4,
        dest: &SocketAddrV4,
        sequence: u32,
        acknowledgement: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut buf = self.packet.clone();
        buf.resize(self.tcp_len + payload.len(), 0);
        let mut packet = MutableTcpPacket::new(&mut buf).unwrap();

        // packet-specific fields
        packet.set_source(source.port());
        packet.set_destination(dest.port());
        packet.set_sequence(sequence);
        packet.set_acknowledgement(acknowledgement);
        packet.set_payload(payload);
        packet.set_checksum(tcp::ipv4_checksum(
            &TcpPacket::new(packet.packet()).unwrap(),
            &source.ip(),
            &dest.ip(),
        ));

        packet.packet().to_vec()
    }
}
