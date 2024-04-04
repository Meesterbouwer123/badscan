use std::{fmt::Display, net::SocketAddrV4, sync::Arc};

use self::{query::QueryResponse, raknet::RaknetReponse};

pub mod query;
pub mod raknet;
pub mod slp;

pub enum Protocol {
    Udp(Arc<UdpProtocol>),
    Tcp(Box<dyn TcpProtocol>),
}

impl Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Udp(proto) => write!(f, "{}", proto.name()),
            Protocol::Tcp(proto) => write!(f, "{}", proto.name()),
        }
    }
}

impl Default for Protocol {
    fn default() -> Self {
        Self::Udp(Arc::new(UdpProtocol::McQuery {
            callback: Box::new(|_, _| panic!("this should not be called")),
            fullstat: false,
        }))
    }
}

impl Protocol {
    pub fn default_port(&self) -> u16 {
        match self {
            Protocol::Udp(proto) => proto.default_port(),
            Protocol::Tcp(proto) => proto.default_port(),
        }
    }
}

// I think that all the problems with the `Protocol` enum can be fixed by making this an enum with all the UDP-based protocols
//TODO: do that
/*pub trait UdpProtocol: Sync + Send {
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
}*/
//#[derive(Clone)]
pub enum UdpProtocol {
    McQuery {
        callback: Box<dyn Fn(&SocketAddrV4, QueryResponse) + Send + Sync>,
        fullstat: bool,
    },
    Raknet {
        callback: Box<dyn Fn(&SocketAddrV4, RaknetReponse) + Send + Sync>,
    },
}

impl UdpProtocol {
    pub fn name(&self) -> String {
        match self {
            UdpProtocol::McQuery { callback: _, fullstat: _ } => "Query".to_string(),
            UdpProtocol::Raknet { callback: _ } => "Raknet".to_string(),
        }
    }

    pub fn default_port(&self) -> u16 {
        match self {
            UdpProtocol::McQuery { callback: _, fullstat: _ } => 25565,
            UdpProtocol::Raknet { callback: _ } => 19132,
        }
    }

    pub fn initial_packet(&self, addr: &SocketAddrV4, cookie: u32) -> Vec<u8> {
        match self {
            UdpProtocol::McQuery { callback: _, fullstat: _ } => query::initial_packet(addr, cookie),
            UdpProtocol::Raknet { callback: _ } => raknet::initial_packet(addr, cookie),
        }
    }

    pub fn handle_packet(
        &self,
        send_back: &dyn Fn(Vec<u8>),
        source: &SocketAddrV4,
        cookie: u32,
        packet: &[u8],
    ) {
        match self {
            UdpProtocol::McQuery { callback, fullstat } => {
                query::handle_packet(send_back, source, cookie, packet, *fullstat, callback)
            }
            UdpProtocol::Raknet { callback } => raknet::handle_packet(send_back, source, cookie, packet, callback),
        }
    }
}

pub trait TcpProtocol: Sync + Send {
    // this is an option because not all protocols start with a client packet
    fn initial_packet(&self, dest: &SocketAddrV4) -> Option<Vec<u8>>;

    fn name(&self) -> String;

    fn default_port(&self) -> u16;
}
