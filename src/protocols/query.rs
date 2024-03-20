use std::{
    collections::HashMap,
    io::Write,
    net::{SocketAddr, SocketAddrV4},
};

use crate::{scanner::StatelessProtocol, utils};

pub enum QueryResponse {
    Partial {
        motd: String,
        gametype: String,
        map: String,
        numplayers: String,
        maxplayers: String,
        host: SocketAddr,
    },
    Full {
        kv_section: HashMap<String, String>,
        players: Vec<String>,
    },
}

const KV_MARKER: [u8; 11] = [
    0x73, 0x70, 0x6C, 0x69, 0x74, 0x6E, 0x75, 0x6D, 0x0, 0x80, 0x0,
];
const PLAYER_MARKER: [u8; 10] = [0x1, 0x70, 0x6C, 0x61, 0x79, 0x65, 0x72, 0x5F, 0x0, 0x0];

impl QueryResponse {
    fn parse_response(response: &[u8], full: bool) -> Result<Self, ()> {
        if full {
            // full stat
            if response.len() < 27 {
                // 1 (type) + 4 (id) + 11 (padding) + 1 (null byte if there are no keys) + 10 (padding) = 27
                return Err(());
            }

            // make sure the marker is correct
            if response[5..16] != KV_MARKER {
                println!(
                    "{:?} != {KV_MARKER:?}",
                    response[5..16]
                        .iter()
                        .map(|c| format!("0x{c:X}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }

            // read K,V section
            let mut i = 16;
            let mut kv_section = HashMap::new();
            loop {
                //key
                let mut key = String::new();
                while response[i] != 0 {
                    key.push(response[i] as char);
                    i += 1;
                }
                i += 1;
                if key.len() == 0 {
                    break;
                }
                //value
                let mut value = String::new();
                while response[i] != 0 {
                    value.push(response[i] as char);
                    i += 1;
                }
                i += 1;
                kv_section.insert(key, value);
            }

            // second marker
            if response[i..i + 10] != PLAYER_MARKER {
                println!(
                    "{:?} !+ {PLAYER_MARKER:?}",
                    response[i..i + 10]
                        .iter()
                        .map(|c| format!("0x{c:X}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }

            // players
            let mut players = vec![];
            loop {
                //player
                let mut player = String::new();
                while response[i] != 0 {
                    player.push(response[i] as char);
                    i += 1;
                }
                i += 1;
                if player.len() == 0 {
                    break;
                }
                players.push(player);
            }

            Ok(Self::Full {
                kv_section,
                players,
            })
        } else {
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
            let hostport = response[i] as u16 + response[i + 1] as u16 * 256;
            i += 2;
            //hostip
            let mut hostip = String::new();
            while response[i] != 0 {
                hostip.push(response[i] as char);
                i += 1;
            }

            Ok(Self::Partial {
                motd,
                gametype,
                map,
                numplayers,
                maxplayers,
                host: SocketAddr::new(hostip.parse().map_err(|_| ())?, hostport),
            })
        }
    }
}

#[derive(Debug, Clone)]
pub struct MinecraftQueryProtocol<F>
where
    F: Fn(&SocketAddrV4, QueryResponse) + Clone + Sync,
{
    callback: F,
    fullstat: bool,
}

impl<F> MinecraftQueryProtocol<F>
where
    F: Fn(&SocketAddrV4, QueryResponse) + Clone + Sync,
{
    pub fn new(callback: F, fullstat: bool) -> Self {
        Self { callback, fullstat }
    }
}

impl<F> StatelessProtocol for MinecraftQueryProtocol<F>
where
    F: Fn(&SocketAddrV4, QueryResponse) + Clone + Sync,
{
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
            println!(
                "{:?} != {}",
                id.to_be_bytes(),
                packet[1..=4]
                    .iter()
                    .map(|c| format!("{:X}", c))
                    .collect::<Vec<_>>()
                    .join(" ")
            );
            return;
        }

        match packet[0] {
            0x09 => {
                // challenge
                if packet.len() < 6 {
                    return;
                }

                let mut token: u32 = 0;
                for i in 5..packet.len() {
                    if i == packet.len() - 1 && packet[i] == 0 {
                        break; // we are done
                    }
                    let digit_char = packet[i] as char;
                    let digit: u32 = match digit_char.to_string().parse() {
                        Ok(val) => val,
                        Err(_) => return,
                    };
                    token = token * 10 + digit;
                }

                // send response packet back
                let mut packet = vec![];
                packet.write(&[0xFE, 0xFD]).unwrap(); // magic
                packet.write(&[0x00]).unwrap(); // intention = handshake
                packet.write(&id.to_be_bytes()).unwrap(); // session ID
                packet.write(&token.to_be_bytes()).unwrap(); // challenge token
                if self.fullstat {
                    packet.write(&[0x00, 0x00, 0x00, 0x00]).unwrap(); // padding
                }

                send_back(packet);
            }
            0x00 => {
                // response
                if let Ok(response) = QueryResponse::parse_response(packet, self.fullstat) {
                    (self.callback)(source, response);
                }
            }
            _ => {
                println!("Unknown packet ID {:X}! (data: {packet:?})", packet[0])
            }
        }
    }
}
