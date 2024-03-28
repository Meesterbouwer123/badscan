use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    net::{IpAddr, Ipv4Addr, SocketAddrV4},
    sync::{
        mpsc::{self, Receiver, Sender},
        Arc, RwLock,
    },
    thread::{self, JoinHandle},
};

use chrono::{DateTime, Utc};
use pnet::{
    datalink::{self, Channel, DataLinkReceiver, DataLinkSender},
    packet::{
        ethernet::{EtherTypes, EthernetPacket},
        ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
        ipv4::{self, Ipv4Packet, MutableIpv4Packet},
        udp::UdpPacket,
        Packet,
    },
};

use crate::{config::CONFIG, interface::MyInterface, protocols::Protocol, utils};

pub struct StatelessScanner {
    _interface: MyInterface,
    protocol: Arc<RwLock<Protocol>>,
    _send_thread: JoinHandle<()>,
    _recv_thread: JoinHandle<()>,
    packet_send: Sender<(SocketAddrV4, Vec<u8>, IpNextHeaderProtocol)>,
    pub start_time: DateTime<Utc>,
    source_ip: Ipv4Addr,
}

impl<'a> StatelessScanner {
    pub fn new(
        interface: &'a MyInterface,
        protocol: Arc<RwLock<Protocol>>,
    ) -> StatelessScanner {
        let interface = interface.clone();
        let start_time = Utc::now();
        let IpAddr::V4(source_ip) = interface.get_source_ip() else {
            panic!("No ipv4 source address!")
        };

        let (network_tx, network_rx) =
            match datalink::channel(&interface.network_interface, Default::default())
                .expect("Could not get channel")
            {
                Channel::Ethernet(tx, rx) => (tx, rx),
                _ => panic!("idk what weird type of connection you have mate"),
            };

        // packet queue
        let (packet_send_tx, packet_send_rx) = mpsc::channel();

        // we first start reading, and only then we start allowing packets to be sent
        // in this case it doesn't matter since it's impossible to send packets at this point, but it's in case an idiot (me) messes with the code
        let recv_thread = {
            let interface = interface.clone();
            let protocol = protocol.clone();
            let packet_send = packet_send_tx.clone();
            let start_time = start_time.clone();
            thread::spawn(move || {
                // receive packets
                Self::recv_thread(interface, network_rx, protocol, packet_send, start_time)
            })
        };

        let send_thread = {
            let interface = interface.clone();
            let source_ip = source_ip.clone();

            thread::spawn(move || {
                Self::send_thread(interface, source_ip, packet_send_rx, network_tx)
            })
        };

        Self {
            _interface: interface,
            protocol,
            _send_thread: send_thread,
            _recv_thread: recv_thread,
            packet_send: packet_send_tx,
            start_time,
            source_ip,
        }
    }

    pub fn scan(&'a mut self, addr: SocketAddrV4) {
        // send initial packet
        let cookie = Self::cookie(&addr, &self.start_time);
        let (packet, proto) = match &*self.protocol.read().unwrap() {
            Protocol::Udp(protocol) => {
                let packet = protocol.initial_packet(&addr, cookie);
                (utils::wrap_udp(packet, &self.source_ip, &addr), IpNextHeaderProtocols::Udp)
            },
        };

        self.send_to(addr, packet, proto);
    }

    fn send_to(&'a mut self, addr: SocketAddrV4, packet: Vec<u8>, protocol: IpNextHeaderProtocol) {
        self.packet_send
            .send((addr, packet, protocol))
            .expect("Could not send packet");
    }

    fn cookie(addr: &SocketAddrV4, start_time: &DateTime<Utc>) -> u32 {
        let mut hasher = DefaultHasher::new();
        (*addr.ip(), addr.port(), CONFIG.scan.seed, start_time.timestamp_millis()).hash(&mut hasher);
        hasher.finish() as u32
    }

    fn recv_thread(
        interface: MyInterface,
        mut rx: Box<dyn DataLinkReceiver>,
        protocol: Arc<RwLock<Protocol>>,
        packet_send: Sender<(SocketAddrV4, Vec<u8>, IpNextHeaderProtocol)>,
        start_time: DateTime<Utc>,
    ) {
        loop {
            match rx.next() {
                Ok(packet) => {
                    let packet = {
                        let packet = EthernetPacket::new(packet).unwrap();
                        if packet.get_destination() != interface.mac() {
                            continue;
                        } // make sure it's meant for us

                        packet.payload().to_vec()
                    };

                    let Some(packet) = Ipv4Packet::new(&packet) else {
                        continue;
                    };

                    match &*protocol.read().unwrap() {
                        Protocol::Udp(proto) => {
                            if packet.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
                                println!("Invalid next level protocol while scanning UDP: {}", packet.get_next_level_protocol());
                                continue;
                            }

                            let udp = UdpPacket::new(packet.payload()).unwrap();
                            /*println!(
                                "UDP from {}:{}, data: {:?}",
                                packet.get_source(),
                                udp.get_source(),
                                udp.payload()
                            );*/

                            let source = SocketAddrV4::new(packet.get_source(), udp.get_source());

                            let cookie = Self::cookie(&source, &start_time);

                            proto.handle_packet(
                                &|packet: Vec<u8>| packet_send.send((source, packet, IpNextHeaderProtocols::Udp)).unwrap(),
                                &source,
                                cookie,
                                udp.payload(),
                            );
                        }
                    }
                }
                Err(_) => todo!(),
            }
        }
    }

    fn send_thread(
        interface: MyInterface,
        source_ip: Ipv4Addr,
        rx: Receiver<(SocketAddrV4, Vec<u8>, IpNextHeaderProtocol)>,
        mut network_tx: Box<dyn DataLinkSender>,
    ) {
        // receive packets form a queue and send them
        while let Ok((dest, packet, protocol)) = rx.recv() {
            let dest: SocketAddrV4 = dest;
            let packet: Vec<u8> = packet;
            // create packet

            // wrap in Ipv4
            let mut ipv4_buf = [0u8; 1024];
            let mut ipv4_packet = MutableIpv4Packet::new(&mut ipv4_buf).unwrap();
            // -- START STEALING FROM MATSCAN --
            ipv4_packet.set_version(4); // ipv4 lol
            ipv4_packet.set_header_length(5); // linux always sets this to 5 - so do we
            ipv4_packet.set_dscp(0); // precedence and delay, don't care so 0
            ipv4_packet.set_ecn(0); // reserved
            ipv4_packet.set_identification(1); // https://github.com/torvalds/linux/blob/master/net/ipv4/ip_output.c#L165
            ipv4_packet.set_flags(0b010);
            ipv4_packet.set_fragment_offset(0); // fragmentation is disabled so 0
            ipv4_packet.set_ttl(128);
            ipv4_packet.set_options(&[]);
            // -- STOP STEALING FROM MATSCAN --
            ipv4_packet.set_next_level_protocol(protocol);
            ipv4_packet.set_total_length(
                (packet.len() + 4 * ipv4_packet.get_header_length() as usize) as u16,
            );
            ipv4_packet.set_payload(&packet);
            ipv4_packet.set_destination(dest.ip().to_owned());
            ipv4_packet.set_source(source_ip);
            ipv4_packet.set_checksum(ipv4::checksum(
                &Ipv4Packet::new(ipv4_packet.packet()).unwrap(),
            ));

            // send packet
            interface.send_packet(&mut network_tx, ipv4_packet.packet(), EtherTypes::Ipv4);
        }
    }
}
