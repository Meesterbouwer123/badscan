use std::{
    collections::HashMap,
    io::{self, Cursor, Read, Write},
    net::{SocketAddr, SocketAddrV4},
};

use byteorder::{LittleEndian, ReadBytesExt};

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

            // read K,V section
            let mut stream = Cursor::new(response);
            let mut buf = [0; 16];
            stream.read(&mut buf).unwrap(); // here we can use .unwrap, because we already checked if we ahve the space

            // make sure the marker is correct
            if buf[5..16] != KV_MARKER {
                println!(
                    "{:?} != {KV_MARKER:?}",
                    buf[5..16]
                        .iter()
                        .map(|c| format!("0x{c:X}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }

            let mut kv_section = HashMap::new();
            loop {
                //key
                let Ok(key) = read_string(&mut stream) else {
                    return Err(());
                };
                if key.len() == 0 {
                    break;
                }
                //value
                let Ok(value) = read_string(&mut stream) else {
                    return Err(());
                };
                kv_section.insert(key, value);
            }

            // second marker
            let mut buf = [0; PLAYER_MARKER.len()];
            stream.read(&mut buf).map_err(|_| ())?;
            if buf != PLAYER_MARKER {
                println!("{buf:?} !+ {PLAYER_MARKER:?}");
            }

            // players
            let mut players = vec![];
            loop {
                //player
                let Ok(player) = read_string(&mut stream) else {
                    return Err(());
                };
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
            let mut stream = Cursor::new(response);
            let mut buf = [0; 5];
            if let Err(_) = stream.read(&mut buf) {
                return Err(());
            }

            //motd
            let Ok(motd) = read_string(&mut stream) else {
                return Err(());
            };
            //gametype
            let Ok(gametype) = read_string(&mut stream) else {
                return Err(());
            };
            //map
            let Ok(map) = read_string(&mut stream) else {
                return Err(());
            };
            //numplayers
            let Ok(numplayers) = read_string(&mut stream) else {
                return Err(());
            };
            //maxplayers
            let Ok(maxplayers) = read_string(&mut stream) else {
                return Err(());
            };
            // hostport
            let Ok(hostport) = stream.read_u16::<LittleEndian>() else {
                return Err(());
            };
            //hostip
            let Ok(hostip) = read_string(&mut stream) else {
                return Err(());
            };

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
    F: Fn(&SocketAddrV4, QueryResponse) + Clone + Sync + Send,
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

        // check if packet can contains enough data
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
                packet.extend_from_slice(&[0xFE, 0xFD]); // magic
                packet.extend_from_slice(&[0x00]); // intention = handshake
                packet.extend_from_slice(&id.to_be_bytes()); // session ID
                packet.extend_from_slice(&token.to_be_bytes()); // challenge token
                if self.fullstat {
                    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // padding
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

    fn name(&self) -> String {
        "Query".to_string()
    }
}

fn read_string(stream: &mut (dyn Read)) -> io::Result<String> {
    let mut string = String::new();
    let mut buf = [0];
    loop {
        stream.read(&mut buf)?;
        if buf[0] == 0 {
            break;
        } else {
            string.push(buf[0] as char)
        }
    }
    Ok(string)
}
