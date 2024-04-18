use std::{
    net::SocketAddrV4,
    sync::{Arc, RwLock},
    thread,
    time::Duration,
};

use badscan::{
    config::{self, CONFIG},
    fingerprint,
    interface::MyInterface,
    protocols::{
        self,
        query::QueryResponse,
        raknet::RaknetReponse,
        slp::MinecraftSlpProtocol,
    },
    tcpscanner::TcpScanner,
    udpscanner::UdpScanner,
};

fn main() {
    println!("Starting BadScan");

    // get interface to use
    println!("Getting interface...");
    let interface = match &CONFIG.interface {
        Some(interface) => MyInterface::from_name(&interface),
        None => MyInterface::get_default(),
    };

    println!(
        "Using interface `{}`: {}",
        interface.network_interface.name,
        interface
            .network_interface
            .ips
            .iter()
            .map(|ip| format!("{ip}"))
            .collect::<Vec<_>>()
            .join(", ")
    );

    // select protocol
    println!("Selecting protocol...");
    let protocol: Arc<RwLock<protocols::Protocol<T>>> = Default::default();
    set_protocol(protocol.clone(), &CONFIG.protocol);
    // select fingerprint
    let fingerprint: Arc<RwLock<fingerprint::Fingerprint>> = Default::default();
    set_fingerprint(fingerprint.clone(), &CONFIG.fingerprint);

    println!(
        "Using protocol: {} with fingerprint {:?}",
        protocol.read().unwrap(),
        CONFIG.fingerprint
    );

    let ranges = SocketAddrV4::new(
        "192.168.2.120".parse().unwrap(),
        protocol.read().unwrap().default_port(),
    );

    // create scanner
    let lock = protocol.read().unwrap();
    match &*lock {
        protocols::Protocol::Udp(proto) => {
            let mut scanner =
                UdpScanner::new(&interface, proto.clone(), &fingerprint.read().unwrap());
            println!(
                "Scanning started at {}",
                scanner.start_time.format("%H:%M %d-%m-%Y UTC")
            );

            scanner.scan(ranges);
        }
        protocols::Protocol::Tcp(proto) => {
            let mut scanner =
                TcpScanner::new(&interface, proto.clone(), &*fingerprint.read().unwrap());
            println!(
                "TCP Scanning started at {}",
                scanner.start_time.format("%H:%M %d-%m-%Y UTC")
            );

            scanner.scan(ranges);
        }
    }

    println!("Scanner done, waiting for the last packets...");
    thread::sleep(Duration::from_secs(CONFIG.scan.wait_delay));
    println!("Done");
}

fn set_protocol<T>(lock: Arc<RwLock<protocols::Protocol<T>>>, protocol: &config::Protocol) {
    let mut lock = lock.write().unwrap();
    *lock = match protocol {
        &config::Protocol::Raknet => {
            protocols::Protocol::Udp(Arc::new(protocols::UdpProtocol::Raknet {
                callback: Box::new(handle_raknet),
            }))
        }
        &config::Protocol::Query { fullstat } => {
            protocols::Protocol::Udp(Arc::new(protocols::UdpProtocol::McQuery {
                callback: Box::new(handle_query),
                fullstat,
            }))
        }
        &config::Protocol::SLP => protocols::Protocol::Tcp(Arc::new(MinecraftSlpProtocol::new())),
    };
}

fn set_fingerprint(lock: Arc<RwLock<fingerprint::Fingerprint>>, fingerprint: &config::Fingerprint) {
    let mut lock = lock.write().unwrap();
    *lock = match fingerprint {
        &config::Fingerprint::Nintendo3DS => fingerprint::Fingerprint::nintendo_3ds(),
    };
}

fn handle_query(addr: &SocketAddrV4, response: QueryResponse) {
    match response {
        QueryResponse::Partial {
            motd,
            gametype,
            map,
            numplayers,
            maxplayers,
            host,
        } => {
            println!("Got partial stat from {addr}: \n\tMOTD = {motd}\n\tgametype = {gametype}\n\tmap = {map}\n\tnumplayers = {numplayers}\n\tmaxplayers = {maxplayers}\n\thost = {host}");
        }
        QueryResponse::Full {
            kv_section,
            players,
        } => {
            let mut output = format!("Got full stat from {addr}:\n");
            output += "=================== K,V section ===================\n";
            for (k, v) in kv_section {
                output += &format!("\t{k} = {v}\n");
            }
            output += "===================== Players =====================\n";
            for player in players {
                output += &format!("\t{player}\n");
            }

            println!("{output}");
        }
    }
}

fn handle_raknet(addr: &SocketAddrV4, response: RaknetReponse) {
    let mut msg = format!(
        "{addr}: GUID = {}, MOTD = `{}`,`{}`, PLAYERS = {}/{}, VERSION = {} {} (protocol v{}), GAMEMODE = {}",
        response.guid,
        response.motd,
        response.sub_motd,
        response.playercount,
        response.maxplayers,
        response.edition,
        response.version,
        response.protocol,
        response.gamemode,
    );

    if let Some(extra) = response.extra {
        msg += &format!(", GARBAGE = `{extra}`");
    }

    println!("{msg}");
}
