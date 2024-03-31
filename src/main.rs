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
        query::{MinecraftQueryProtocol, QueryResponse},
        raknet::{RaknetProtocol, RaknetReponse},
        slp::MinecraftSlpProtocol,
    },
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
    let protocol: Arc<RwLock<protocols::Protocol>> = Default::default();
    set_protocol(protocol.clone(), &CONFIG.protocol);
    // select fingerprint
    let fingerprint: Arc<RwLock<fingerprint::Fingerprint>> = Default::default();
    set_fingerprint(fingerprint.clone(), &CONFIG.fingerprint);

    println!(
        "Using protocol: {} with fingerprint {:?}",
        protocol.read().unwrap(),
        CONFIG.fingerprint
    );

    // create scanner
    let lock = protocol.read().unwrap();
    match &*lock {
        &protocols::Protocol::Udp(proto) => {
            let protocol = Arc::new(proto);
            let mut scanner = UdpScanner::new(&interface, protocol.clone(), fingerprint.clone());
            println!(
                "Scanning started at {}",
                scanner.start_time.format("%H:%M %d-%m-%Y UTC")
            );

            scanner.scan(SocketAddrV4::new(
                "192.168.2.120".parse().unwrap(),
                protocol.default_port(),
            ));
        }
        &protocols::Protocol::Tcp(_) => todo!("re-add TCP scanning"),
    }

    println!("Scanner done, waiting for the last packets...");
    thread::sleep(Duration::from_secs(CONFIG.scan.wait_delay));
    println!("Done");
}

fn set_protocol(lock: Arc<RwLock<protocols::Protocol>>, protocol: &config::Protocol) {
    let mut lock = lock.write().unwrap();
    *lock = match protocol {
        &config::Protocol::Raknet => {
            protocols::Protocol::Udp(Box::new(RaknetProtocol::new(handle_raknet)))
        }
        &config::Protocol::Query { fullstat } => protocols::Protocol::Udp(Box::new(
            MinecraftQueryProtocol::new(handle_query, fullstat),
        )),
        &config::Protocol::SLP => protocols::Protocol::Tcp(Box::new(MinecraftSlpProtocol::new())),
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
