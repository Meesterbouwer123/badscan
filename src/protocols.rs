use std::{fmt::Display, net::SocketAddrV4};

use self::query::MinecraftQueryProtocol;

pub mod query;
pub mod raknet;

pub enum Protocol {
    Udp(Box<dyn UdpProtocol>),
}

impl Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Udp(proto) => write!(f, "{}", proto.name()),
        }
    }
}

impl Default for Protocol {
    fn default() -> Self {
        Self::Udp(Box::new(MinecraftQueryProtocol::new(|_, _| {panic!("Shouldn't be called")}, false)))
    }
}

impl Protocol {
    pub fn default_port(&self) -> u16 {
        match self {
            Protocol::Udp(proto) => proto.default_port(),
        }
    }
}

pub trait UdpProtocol: Sync + Send {
    fn initial_packet(&self, addr: &SocketAddrV4, cookie: u32) -> Vec<u8>;

    fn handle_packet(
        &self,
        send_back: &dyn Fn(Vec<u8>),
        source: &SocketAddrV4,
        cookie: u32,
        packet: &[u8],
    );

    fn name(&self) -> String;

    fn default_port(&self) -> u16;
}