use std::net::IpAddr;

use pnet::{
    datalink::{self, DataLinkSender, NetworkInterface},
    packet::{
        ethernet::{EtherType, MutableEthernetPacket},
        Packet,
    },
    util::MacAddr,
};

#[derive(Debug, Clone)]
pub struct MyInterface {
    pub network_interface: NetworkInterface,
    pub gateway_mac: Option<MacAddr>,
}

impl MyInterface {
    pub fn get_default() -> Self {
        let default_interface =
            default_net::get_default_interface().expect("Could not get default interface");
        Self::from_default(&default_interface)
    }

    pub fn from_name(name: &str) -> Self {
        let interfaces = default_net::get_interfaces();
        let default_interface = interfaces
            .iter()
            .find(|interface| interface.name == name)
            .expect("Could not find interface");
        Self::from_default(default_interface)
    }

    fn from_default(default_interface: &default_net::Interface) -> Self {
        let Some(mac) = default_interface.mac_addr else {
            panic!("Interface doesn't have a MAC address!")
        };
        let mac = convert_mac(mac);
        let gateway_mac = default_interface
            .clone()
            .gateway
            .map(|gateway| convert_mac(gateway.mac_addr));

        // turn into pnet's NetworkInterface
        let network_interface = datalink::interfaces()
            .iter()
            .find(|interface| interface.mac == Some(mac))
            .expect("Could not get interface")
            .to_owned();

        MyInterface {
            network_interface,
            gateway_mac,
        }
    }

    pub fn get_source_ip(&self) -> IpAddr {
        self.network_interface
            .ips
            .iter()
            .find(|ip| ip.is_ipv4())
            .unwrap()
            .ip()
    }

    pub fn mac(&self) -> MacAddr {
        self.network_interface.mac.unwrap()
    }

    pub fn send_packet(
        &self,
        tx: &mut Box<dyn DataLinkSender>,
        packet: &[u8],
        ethertype: EtherType,
    ) {
        // wrap into ethernet
        let packet = match self.gateway_mac {
            Some(dest) => {
                let mut ethernet_buf = [0u8; 1024 + 20]; // ethernet header should be 20 bytes

                let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buf).unwrap();
                ethernet_packet.set_destination(dest);
                ethernet_packet.set_source(self.network_interface.mac.unwrap());
                ethernet_packet.set_ethertype(ethertype);
                ethernet_packet.set_payload(packet);

                ethernet_packet.packet().to_vec()
            }
            None => packet.to_vec(),
        };

        tx.send_to(&packet, None);
    }
}

// helper function
fn convert_mac(mac: default_net::mac::MacAddr) -> MacAddr {
    MacAddr::from(mac.octets())
}
