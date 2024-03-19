
use std::{io::Write, net::SocketAddrV4, thread, time::Duration};

use scanner::StatelessProtocol;

mod config;
mod interface;
mod scanner;
mod utils;
use crate::{config::CONFIG, interface::MyInterface, scanner::StatelessScanner};

struct MinecraftQueryProtocol {}

impl MinecraftQueryProtocol {
    fn parse_response(&self, addr: &SocketAddrV4, response: &[u8]) {
        if response.len() > 16 && response[5..=16] == [0x73, 0x70, 0x6C, 0x69, 0x74, 0x6E, 0x75, 0x6D, 0x00, 0x80, 0x00] {
            // full stat
            todo!("Add full stat");
        }
        else {
            // partial stat
            let mut i = 5;

            //motd
            let mut motd = String::new();
            while response[i] != 0 {
                motd.push(response[i] as char);
                i += 1;
            }
            i += 1;
            //gametype
            let mut gametype = String::new();
            while response[i] != 0 {
                gametype.push(response[i] as char);
                i += 1;
            }
            i += 1;
            //map
            let mut map = String::new();
            while response[i] != 0 {
                map.push(response[i] as char);
                i += 1;
            }
            i += 1;
            //numplayers
            let mut numplayers = String::new();
            while response[i] != 0 {
                numplayers.push(response[i] as char);
                i += 1;
            }
            i += 1;
            //maxplayers
            let mut maxplayers = String::new();
            while response[i] != 0 {
                maxplayers.push(response[i] as char);
                i += 1;
            }
            i += 1;
            // hostport
            let hostport = response[i] as u16 + response[i+1] as u16 * 256;
            i += 2;
            //hostip
            let mut hostip = String::new();
            while response[i] != 0 {
                hostip.push(response[i] as char);
                i += 1;
            }

            println!("Got partial stat from {addr}: \n\tMOTD = {motd}\n\tgametype = {gametype}\n\tmap = {map}\n\tnumplayers = {numplayers}\n\tmaxplayers = {maxplayers}\n\thost = {hostip}:{hostport}");
        }
    }
}

impl StatelessProtocol for MinecraftQueryProtocol {
    fn initial_packet(&self, addr: &SocketAddrV4) -> Vec<u8> {
        let id = utils::cookie(addr) & 0x0F0F0F0F;
        
        let mut packet = vec![];
        packet.write(&[0xFE, 0xFD]).unwrap(); // magic
        packet.write(&[0x09]).unwrap(); // intention = handshake
        packet.write(&id.to_be_bytes()).unwrap(); // session ID

        packet
    }

    fn handle_packet(&self, send_back: &dyn Fn(Vec<u8>), source: &SocketAddrV4, packet: &[u8]) {
        //println!("got packet from {source}: {packet:?}");

        // check if packet can containenough data
        if packet.len() < 5 {
            return;
        }

        let id = utils::cookie(source) & 0x0F0F0F0F;
        // make sure ID is correct
        if id.to_be_bytes() != packet[1..=4] {
            println!("{:?} != {}", id.to_be_bytes(), packet[1..=4].iter().map(|c| format!("{:X}", c)).collect::<Vec<_>>().join(" "));
            return;
        }

        match packet[0] {
            0x09 => {
                // challenge
                if packet.len() < 6 {return;}

                let mut token: u32 = 0;
                for i in 5..packet.len() {
                    if i == packet.len() - 1 && packet[i] == 0 {
                        break;  // we are done
                    }
                    let digit_char = packet[i]as char;
                    let digit: u32 = match digit_char.to_string().parse() {
                        Ok(val) => val,
                        Err(_) => return
                    };
                    token = token * 10 + digit;
                }

                // send response packet back
                let mut packet = vec![];
                packet.write(&[0xFE, 0xFD]).unwrap();   // magic
                packet.write(&[0x00]).unwrap(); // intention = handshake
                packet.write(&id.to_be_bytes()).unwrap();   // session ID
                packet.write(&token.to_be_bytes()).unwrap();    // challenge token

                send_back(packet);
            }
            0x00 => {
                // response
                self.parse_response(source, packet);
            }
            _ => {
                println!("Unknown packet ID {:X}! (data: {packet:?})", packet[0])
            }
        }
    }
}

fn main() {
    // get interface to use
    let interface = match &CONFIG.interface {
        Some(interface) => MyInterface::from_name(&interface),
        None => MyInterface::get_default(),
    };

    println!(
        "Using interface `{}` ({}): {}",
        interface.network_interface.description,
        interface.network_interface.name,
        interface
            .network_interface
            .ips
            .iter()
            .map(|ip| format!("{ip}"))
            .collect::<Vec<_>>()
            .join(", ")
    );

    // create scanner
    let mut scanner = StatelessScanner::new(&interface, MinecraftQueryProtocol {});

    scanner.scan(SocketAddrV4::new("192.168.2.120".parse().unwrap(), 25565));
    thread::sleep(Duration::from_secs(1));
}
