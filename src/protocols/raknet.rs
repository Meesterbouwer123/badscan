use std::{
    io::{self, Cursor, Read},
    net::SocketAddrV4,
};

use byteorder::{BigEndian, ReadBytesExt};

use crate::{
    scanner::StatelessProtocol,
    utils::{self, cookie},
};

const MAGIC: [u8; 16] = [
    0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe, 0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78,
];

#[derive(Debug)]
pub struct RaknetReponse {
    pub source: String,
    pub edition: String,
    pub motd: String,
    pub protocol: usize,
    pub version: String,
    pub playercount: isize,
    pub maxplayers: isize,
    pub guid: u64,
    pub sub_motd: String,
    pub gamemode: String,
    pub num_gamemode: isize,
    pub port_ipv4: u16,
    pub port_ipv6: u16,
    pub extra: Option<String>,
}

impl RaknetReponse {
    fn new(guid: u64, server_id: String) -> Result<Self, ()> {
        // server_id format: edition;MOTD;protocol;version;playercount;maxplayers;GUID;sub-MOTD;game mode;game mode(numeric);port(IPv4);port(IPv6); (and probably some extra data)
        let mut parts = server_id.split(';');
        // edition
        let Some(edition) = parts.next() else {
            return Err(());
        };
        // motd
        let Some(motd) = parts.next() else {
            return Err(());
        };
        // protocol
        let Ok(protocol) = parts
            .next()
            .ok_or(())
            .and_then(|protocol| protocol.parse::<usize>().map_err(|_| ()))
        else {
            return Err(());
        };
        // version
        let Some(version) = parts.next() else {
            return Err(());
        };
        // player count
        let Ok(playercount) = parts
            .next()
            .ok_or(())
            .and_then(|playercount| playercount.parse().map_err(|_| ()))
        else {
            return Err(());
        };
        // player cap
        let Ok(maxplayers) = parts
            .next()
            .ok_or(())
            .and_then(|maxplayers| maxplayers.parse().map_err(|_| ()))
        else {
            return Err(());
        };
        // validate that the GUID is identical
        if let Some(str_guid) = parts.next() {
            if str_guid != format!("{guid}") {
                println!("GUID doesn't match, {guid} != {str_guid}");
                return Err(());
            }
        } else {
            return Err(());
        }
        // sub-motd
        let Some(sub_motd) = parts.next() else {
            return Err(());
        };
        // gamemode
        let Some(gamemode) = parts.next() else {
            return Err(());
        };
        // gamemode 2: electric boogaloo
        let Ok(num_gamemode) = parts
            .next()
            .ok_or(())
            .and_then(|num_gamemode| num_gamemode.parse().map_err(|_| ()))
        else {
            return Err(());
        };
        // IPv4 port
        let Ok(port_ipv4) = parts
            .next()
            .ok_or(())
            .and_then(|port_ipv4| port_ipv4.parse().map_err(|_| ()))
        else {
            return Err(());
        };
        // IPv6 port
        let Ok(port_ipv6) = parts
            .next()
            .ok_or(())
            .and_then(|port_ipv6| port_ipv6.parse().map_err(|_| ()))
        else {
            return Err(());
        };
        // extra garbage data
        let parts: Vec<&str> = parts.collect();
        let extra: Option<String> = if parts == [""] {
            None
        } else {
            Some(
                parts
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<String>>()
                    .join(";"),
            )
        };

        // return the structure
        Ok(Self {
            edition: String::from(edition),
            motd: String::from(motd),
            protocol,
            version: String::from(version),
            playercount,
            maxplayers,
            guid,
            sub_motd: String::from(sub_motd),
            gamemode: String::from(gamemode),
            num_gamemode,
            port_ipv4,
            port_ipv6,
            extra,
            source: server_id,
        })
    }
}

#[derive(Debug, Clone)]
pub struct RaknetProtocol<F>
where
    F: Fn(&SocketAddrV4, RaknetReponse) + Clone + Sync,
{
    callback: F,
}

impl<F> RaknetProtocol<F>
where
    F: Fn(&SocketAddrV4, RaknetReponse) + Clone + Sync,
    Self: Send + Sync + Sized,
{
    pub fn new(callback: F) -> Self {
        Self { callback }
    }
}

impl<F> StatelessProtocol for RaknetProtocol<F>
where
    F: Fn(&SocketAddrV4, RaknetReponse) + Clone + Sync + Send,
{
    fn initial_packet(&self, addr: &std::net::SocketAddrV4) -> Vec<u8> {
        let cookie = utils::cookie(addr);
        let mut packet = vec![];
        packet.extend_from_slice(&[0x01]); // packet ID
        packet.extend_from_slice(&cookie.to_be_bytes()); // for some reason the server sends our timestamp back lol
        packet.extend_from_slice(&cookie.to_be_bytes()); // we will 100% abuse this to contain our cookie
        packet.extend_from_slice(&MAGIC); // magic
        packet.extend_from_slice(&[0u8; 8]); // GUID

        packet
    }

    fn handle_packet(
        &self,
        _send_back: &dyn Fn(Vec<u8>),
        source: &std::net::SocketAddrV4,
        packet: &[u8],
    ) {
        // remember, we can't use .unwrap() here since then possible attackers could crash our scanner
        let cookie = cookie(source);

        // size check
        // 1 (packet ID) + 8 (timestamp) + 8 (server GUID) + MAGIC + 2 (short to the string) = 19
        if packet.len() <= 19 + MAGIC.len() {
            return;
        }

        let mut stream = Cursor::new(packet);

        // packet ID
        let Ok(packet_id) = stream.read_u8() else {
            return;
        };
        if packet_id != 0x1c {
            return;
        }

        // client timestamp, we store the cookie here
        let Ok(timestamp) = stream.read_u64::<BigEndian>() else {
            return;
        };

        if (timestamp & u32::MAX as u64) as u32 != cookie
            || ((timestamp >> 32) & u32::MAX as u64) as u32 != cookie
        // fun fact: the >> operation shifts by bits, not bytes
        {
            println!(
                "wrong cookie!, expected 2x {cookie:X}, got {:X} and {:X}",
                timestamp & u32::MAX as u64,
                (timestamp >> 32) & u32::MAX as u64
            );
            return;
        }

        // server GUID
        let Ok(guid) = stream.read_u64::<BigEndian>() else {
            return;
        };

        // magic
        let Ok(magic) = read_bytes(&mut stream, MAGIC.len()) else {
            return;
        };
        if magic != MAGIC {
            println!("bad magic");
            return;
        }

        // server id
        let Ok(server_id_len) = stream.read_u16::<BigEndian>() else {
            return;
        };

        let Ok(server_id) = read_bytes(&mut stream, server_id_len as usize) else {
            return;
        };

        let Ok(server_id) = String::from_utf8(server_id) else {
            return;
        };

        let Ok(response) = RaknetReponse::new(guid, server_id) else {
            return;
        };

        (self.callback)(source, response);
    }

    fn name(&self) -> String {
        "Raknet".to_string()
    }
}

fn read_bytes(stream: &mut (dyn Read), length: usize) -> io::Result<Vec<u8>> {
    let mut bytes = vec![];
    for _ in 0..length {
        let mut buf = [0];
        stream.read(&mut buf)?;
        bytes.push(buf[0]);
    }

    Ok(bytes)
}
