use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    net::{IpAddr, SocketAddrV4},
    sync::{
        mpsc::{self, Sender},
        Arc, RwLock,
    },
    thread::{self, JoinHandle},
    time::Instant,
};

use pnet::{
    datalink::{self, Channel},
    packet::{
        ethernet::{EtherTypes, EthernetPacket},
        ip::IpNextHeaderProtocols,
        ipv4::{self, Ipv4Packet, MutableIpv4Packet},
        udp::{self, MutableUdpPacket, UdpPacket},
        Packet,
    },
};

use crate::{config::CONFIG, interface::MyInterface};

// constants
pub const UDP_HEADER_LEN: usize = 8;

pub trait StatelessProtocol: Sync + Send {
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

pub struct StatelessScanner {
    _interface: MyInterface,
    protocol: Arc<RwLock<Box<dyn StatelessProtocol>>>,
    _send_thread: JoinHandle<()>,
    _recv_thread: JoinHandle<()>,
    packet_send: Sender<(SocketAddrV4, Vec<u8>)>,
    start_time: Instant,
}

impl<'a> StatelessScanner {
    pub fn new(
        interface: &'a MyInterface,
        protocol: Arc<RwLock<Box<dyn StatelessProtocol>>>,
    ) -> StatelessScanner {
        let interface = interface.clone();
        let start_time = Instant::now();

        let (mut network_tx, mut network_rx) =
            match datalink::channel(&interface.network_interface, Default::default())
                .expect("Could not get channel")
            {
                Channel::Ethernet(tx, rx) => (tx, rx),
                _ => panic!("idk what weird type of connection you have mate"),
            };

        // packet queue
        let (packet_send_tx, packet_send_rx) = mpsc::channel();

        let send_thread = {
            let interface = interface.clone();
            let IpAddr::V4(source_ip) = interface.get_source_ip() else {
                panic!("no ipv4!")
            };

            thread::spawn(move || {
                // receive packets form a queue and send them
                while let Ok((dest, packet)) = packet_send_rx.recv() {
                    let dest: SocketAddrV4 = dest;
                    let packet: Vec<u8> = packet;
                    // send packet
                    // wrap in udp
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
                    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
                    ipv4_packet.set_total_length(
                        (udp_packet.packet().len() + 4 * ipv4_packet.get_header_length() as usize)
                            as u16,
                    );
                    ipv4_packet.set_payload(&udp_packet.packet());
                    ipv4_packet.set_destination(dest.ip().to_owned());
                    ipv4_packet.set_source(source_ip);
                    ipv4_packet.set_checksum(ipv4::checksum(
                        &Ipv4Packet::new(ipv4_packet.packet()).unwrap(),
                    ));

                    // send packet
                    interface.send_packet(&mut network_tx, ipv4_packet.packet(), EtherTypes::Ipv4);
                }
            })
        };

        // it would be best practice to first start listening and only when that's done we start scanning, but because we are in the constructor you can't start sending packets until everything started up already
        let recv_thread = {
            let interface = interface.clone();
            let protocol = protocol.clone();
            let packet_send = packet_send_tx.clone();
            let start_time = start_time.clone();
            thread::spawn(move || {
                // receive packets
                loop {
                    match network_rx.next() {
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

                            match packet.get_next_level_protocol() {
                                IpNextHeaderProtocols::Udp => {
                                    let udp = UdpPacket::new(packet.payload()).unwrap();
                                    /*println!(
                                        "UDP from {}:{}, data: {:?}",
                                        packet.get_source(),
                                        udp.get_source(),
                                        udp.payload()
                                    );*/

                                    let source =
                                        SocketAddrV4::new(packet.get_source(), udp.get_source());

                                    let cookie = Self::cookie(&source, &start_time);

                                    protocol.read().unwrap().handle_packet(
                                        &|packet: Vec<u8>| {
                                            packet_send.send((source, packet)).unwrap()
                                        },
                                        &source,
                                        cookie,
                                        udp.payload(),
                                    );
                                }
                                _ => {
                                    println!(
                                        "Unknown protocol: {}",
                                        packet.get_next_level_protocol()
                                    )
                                }
                            }
                        }
                        Err(_) => todo!(),
                    }
                }
            })
        };

        Self {
            _interface: interface,
            protocol,
            _send_thread: send_thread,
            _recv_thread: recv_thread,
            packet_send: packet_send_tx,
            start_time,
        }
    }

    pub fn scan(&'a mut self, addr: SocketAddrV4) {
        // send initial packet
        let cookie = Self::cookie(&addr, &self.start_time);
        let packet = self.protocol.read().unwrap().initial_packet(&addr, cookie);
        self.send_to(addr, packet);
    }

    fn send_to(&'a mut self, addr: SocketAddrV4, packet: Vec<u8>) {
        self.packet_send
            .send((addr, packet))
            .expect("Could not send packet");
    }

    pub fn cookie(addr: &SocketAddrV4, start_time: &Instant) -> u32 {
        let mut hasher = DefaultHasher::new();
        (*addr.ip(), addr.port(), CONFIG.scan.seed, start_time).hash(&mut hasher);
        hasher.finish() as u32
    }
}
