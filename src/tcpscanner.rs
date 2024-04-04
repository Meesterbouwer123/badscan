use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    net::{IpAddr, Ipv4Addr, SocketAddrV4},
    sync::{
        mpsc::{self, Receiver, Sender},
        Arc,
    },
    thread::{self, JoinHandle},
};

use chrono::{DateTime, Utc};
use pnet::{
    datalink::{self, Channel, DataLinkReceiver, DataLinkSender},
    packet::{
        ethernet::{EtherTypes, EthernetPacket},
        ip::IpNextHeaderProtocols,
        ipv4::{self, Ipv4Flags, Ipv4Packet, MutableIpv4Packet},
        tcp::{TcpFlags, TcpPacket},
        Packet,
    },
};

use crate::{
    config::CONFIG, fingerprint::Fingerprint, interface::MyInterface, protocols::TcpProtocol,
};

pub struct TcpScanner {
    _interface: MyInterface,
    _send_thread: JoinHandle<()>,
    _recv_thread: JoinHandle<()>,
    packet_send: Sender<(SocketAddrV4, Vec<u8>)>,
    pub start_time: DateTime<Utc>,
    source_ip: Ipv4Addr,
    fingerprint: Fingerprint,
}

const IPV4_HEADER_SIZE: usize = 20;

impl<'a> TcpScanner {
    pub fn new(
        interface: &'a MyInterface,
        protocol: Arc<dyn TcpProtocol>,
        fingerprint: &Fingerprint,
    ) -> TcpScanner {
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
            let fingerprint = fingerprint.clone();
            thread::spawn(move || {
                // receive packets
                Self::recv_thread(
                    interface,
                    network_rx,
                    protocol,
                    packet_send,
                    start_time,
                    &fingerprint,
                )
            })
        };

        let send_thread = {
            let interface = interface.clone();
            let source_ip = source_ip.clone();
            let fingerprint = fingerprint.clone();
            thread::spawn(move || {
                Self::send_thread(
                    interface,
                    fingerprint,
                    source_ip,
                    packet_send_rx,
                    network_tx,
                )
            })
        };

        Self {
            _interface: interface,
            _send_thread: send_thread,
            _recv_thread: recv_thread,
            packet_send: packet_send_tx,
            start_time,
            source_ip,
            fingerprint: fingerprint.clone(),
        }
    }

    pub fn scan(&'a mut self, addr: SocketAddrV4) {
        // send initial packet
        let cookie = Self::cookie(&addr, &self.start_time);
        let source = SocketAddrV4::new(self.source_ip, 61000);
        let packet = self
            .fingerprint
            .get_syn()
            .create(&source, &addr, cookie, 0, &[]);

        self.send_to(addr, packet);
    }

    fn send_to(&'a mut self, addr: SocketAddrV4, packet: Vec<u8>) {
        self.packet_send
            .send((addr, packet))
            .expect("Could not send packet");
    }

    fn cookie(addr: &SocketAddrV4, start_time: &DateTime<Utc>) -> u32 {
        let mut hasher = DefaultHasher::new();
        (
            *addr.ip(),
            addr.port(),
            CONFIG.scan.seed,
            start_time.timestamp_millis(),
        )
            .hash(&mut hasher);
        hasher.finish() as u32
    }

    fn recv_thread(
        interface: MyInterface,
        mut rx: Box<dyn DataLinkReceiver>,
        protocol: Arc<dyn TcpProtocol>,
        packet_send: Sender<(SocketAddrV4, Vec<u8>)>,
        start_time: DateTime<Utc>,
        fingerprint: &Fingerprint,
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

                    // nothing wrong with using &* :D
                    if packet.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
                        println!(
                            "Invalid next level protocol while scanning TCP: {}",
                            packet.get_next_level_protocol()
                        );
                        continue;
                    }

                    let tcp_packet = TcpPacket::new(packet.payload()).unwrap();
                    let source = SocketAddrV4::new(packet.get_source(), tcp_packet.get_source());
                    let dest =
                        SocketAddrV4::new(packet.get_destination(), tcp_packet.get_destination());
                    let cookie = Self::cookie(&source, &start_time);
                    println!(
                        "Got TCP packet from {}:{}, flags = {:b}",
                        packet.get_source(),
                        tcp_packet.get_source(),
                        tcp_packet.get_flags()
                    );

                    // SYN-ACK
                    if tcp_packet.get_flags() & TcpFlags::SYN != 0
                        && tcp_packet.get_flags() & TcpFlags::ACK != 0
                    {
                        // validate cookie
                        if tcp_packet.get_acknowledgement() != cookie + 1 {
                            println!(
                                "Invalid cookie! expected {} but got {}",
                                cookie + 1,
                                tcp_packet.get_acknowledgement()
                            );
                            // send RST back
                            println!("Sending RST back");
                            let rst = fingerprint.get_rst().create(
                                &dest,
                                &source,
                                tcp_packet.get_acknowledgement(),
                                tcp_packet.get_sequence() + 1,
                                &[],
                            );
                            packet_send.send((source, rst)).unwrap();
                            continue;
                        }

                        // sending ACK
                        // apparently the sequence and the acknowledgement need to be swapped, no clue why
                        let ack = fingerprint.get_ack().create(
                            &dest,
                            &source,
                            tcp_packet.get_acknowledgement(),
                            tcp_packet.get_sequence() + 1,
                            &[],
                        );

                        packet_send.send((source, ack)).unwrap();

                        if let Some(data) = protocol.initial_packet(&source) {
                            // send data
                            let packet = fingerprint.get_psh().create(
                                &dest,
                                &source,
                                tcp_packet.get_acknowledgement(),
                                tcp_packet.get_sequence() + 1,
                                &data,
                            );
                            packet_send.send((source, packet)).unwrap();
                        }
                    } else if !tcp_packet.payload().is_empty() {
                        println!("data: {:?}", tcp_packet.payload());

                        // ack this data
                        let ack = fingerprint.get_ack().create(
                            &dest,
                            &source,
                            tcp_packet.get_acknowledgement(),
                            tcp_packet.get_sequence() + tcp_packet.payload().len() as u32,
                            &[],
                        );

                        packet_send.send((source, ack)).unwrap();
                    } else if tcp_packet.get_flags() & TcpFlags::RST != 0 {
                        println!("RST :(");
                    } else {
                        println!("Unknown flags: {:b}", tcp_packet.get_flags());
                    }
                }
                Err(_) => todo!(),
            }
        }
    }

    fn send_thread(
        interface: MyInterface,
        fingerprint: Fingerprint,
        source_ip: Ipv4Addr,
        rx: Receiver<(SocketAddrV4, Vec<u8>)>,
        mut network_tx: Box<dyn DataLinkSender>,
    ) {
        // receive packets form a queue and send them
        while let Ok((dest, packet)) = rx.recv() {
            let dest: SocketAddrV4 = dest;
            let packet: Vec<u8> = packet;
            // create packet

            // wrap in Ipv4
            let mut ipv4_buf = vec![0u8; packet.len() + IPV4_HEADER_SIZE];
            let mut ipv4_packet = MutableIpv4Packet::new(&mut ipv4_buf).unwrap();
            // -- START STEALING FROM MATSCAN --
            ipv4_packet.set_version(4); // ipv4 lol
            ipv4_packet.set_dscp(0); // precedence and delay, don't care so 0
            ipv4_packet.set_ecn(0); // reserved
            ipv4_packet.set_identification(1); // https://github.com/torvalds/linux/blob/master/net/ipv4/ip_output.c#L165
            ipv4_packet.set_fragment_offset(0); // fragmentation is disabled so 0
            ipv4_packet.set_options(&[]);
            // -- STOP STEALING FROM MATSCAN --
            ipv4_packet.set_flags(Ipv4Flags::DontFragment); // please, it would make it so much easier
            ipv4_packet.set_header_length(IPV4_HEADER_SIZE as u8 / 4);
            ipv4_packet.set_ttl(fingerprint.ittl);
            ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
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
