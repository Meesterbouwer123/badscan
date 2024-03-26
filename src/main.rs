use std::{
    net::SocketAddrV4,
    sync::{Arc, RwLock},
    thread,
    time::Duration,
};

use badscan::{
    config::{Protocol, CONFIG},
    interface::MyInterface,
    protocols::{query::{MinecraftQueryProtocol, QueryResponse}, raknet::RaknetProtocol},
    scanner::{StatelessProtocol, StatelessScanner},
};

fn main() {
    println!();
    // get interface to use
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
    let protocol: Arc<RwLock<Box<dyn StatelessProtocol>>> = Arc::new(RwLock::new(Box::new(
        MinecraftQueryProtocol::new(|_, _| panic!("this should not be called"), true),
    )));

    {
        let mut protocol = protocol.write().unwrap();
        *protocol = match CONFIG.protocol {
            Protocol::Raknet => Box::new(RaknetProtocol::new()),
            Protocol::Query { fullstat } => {
                Box::new(MinecraftQueryProtocol::new(handle_query, fullstat))
            }
        };
    }
    println!("using protocol: {}", protocol.read().unwrap().name());

    // create scanner
    let mut scanner = StatelessScanner::new(&interface, protocol.clone());

    scanner.scan(SocketAddrV4::new("192.168.2.120".parse().unwrap(), 19132));
    thread::sleep(Duration::from_secs(5));
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
