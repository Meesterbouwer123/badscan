use std::{fmt::Display, net::SocketAddrV4, sync::Arc};

use thiserror::Error;

use crate::tcpscanner::TcpState;

use self::{query::QueryResponse, raknet::RaknetReponse};

pub mod query;
pub mod raknet;
pub mod slp;

pub enum Protocol<T> {
    Udp(Arc<UdpProtocol>),
    Tcp(Arc<dyn TcpProtocol<T>>),
}

impl<T> Display for Protocol<T>
where
    T: Default,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Udp(proto) => write!(f, "{}", proto.name()),
            Protocol::Tcp(proto) => write!(f, "{}", proto.name()),
        }
    }
}

impl<T> Default for Protocol<T>
where
    T: Default,
{
    fn default() -> Self {
        Self::Udp(Arc::new(UdpProtocol::McQuery {
            callback: Box::new(|_, _| panic!("this should not be called")),
            fullstat: false,
        }))
    }
}

impl<T> Protocol<T>
where
    T: Default,
{
    pub fn default_port(&self) -> u16 {
        match self {
            Protocol::Udp(proto) => proto.default_port(),
            Protocol::Tcp(proto) => proto.default_port(),
        }
    }
}

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
            UdpProtocol::McQuery {
                callback: _,
                fullstat: _,
            } => "Query".to_string(),
            UdpProtocol::Raknet { callback: _ } => "Raknet".to_string(),
        }
    }

    pub fn default_port(&self) -> u16 {
        match self {
            UdpProtocol::McQuery {
                callback: _,
                fullstat: _,
            } => 25565,
            UdpProtocol::Raknet { callback: _ } => 19132,
        }
    }

    pub fn initial_packet(&self, addr: &SocketAddrV4, cookie: u32) -> Vec<u8> {
        match self {
            UdpProtocol::McQuery {
                callback: _,
                fullstat: _,
            } => query::initial_packet(addr, cookie),
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
            UdpProtocol::Raknet { callback } => {
                raknet::handle_packet(send_back, source, cookie, packet, callback)
            }
        }
    }
}

#[derive(Error, Debug)]
pub enum TcpError {
    #[error("The stream wasn't yet complete")]
    Incomplete,
}

pub trait TcpProtocol<T>: Sync + Send
where
    T: Default,
{
    // this is an option because not all protocols start with a client packet
    fn initial_packet(&self, dest: &SocketAddrV4) -> Option<Vec<u8>>;

    fn name(&self) -> String;

    fn default_port(&self) -> u16;

    fn handle_data(
        &self,
        source: &SocketAddrV4,
        state: &mut TcpState<T>,
    ) -> Result<usize, TcpError>;
}
