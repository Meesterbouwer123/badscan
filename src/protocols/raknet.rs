use std::io::Write;

use crate::{scanner::StatelessProtocol, utils};

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
        let _cookie = utils::cookie(addr);
        let mut packet = vec![];
        packet.write(&[0x01]).unwrap(); // packet ID
        packet.write(&[0u8; 8]).unwrap(); // timestamp (TODO: make this actually show the timestamp)
        packet.write(&MAGIC).unwrap(); // magic
        packet.write(&[0u8; 8]).unwrap(); // GUID (TODO: make this contain the cookie)

        packet
    }

    fn handle_packet(
        &self,
        _send_back: &dyn Fn(Vec<u8>),
        _source: &std::net::SocketAddrV4,
        packet: &[u8],
    ) {
        println!("packet: {packet:?}");
        todo!()
    }
}
