use std::{net::SocketAddrV4, thread, time::Duration};

mod config;
mod interface;
mod protocols;
mod scanner;
mod utils;
use protocols::{query::QueryResponse, raknet::RaknetProtocol};
use scanner::StatelessProtocol;

use crate::{
    config::CONFIG, interface::MyInterface, protocols::query::MinecraftQueryProtocol,
    scanner::StatelessScanner,
};

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
    let protocol = get_protocol();
    let mut scanner = StatelessScanner::new(&interface, protocol);

    scanner.scan(SocketAddrV4::new("192.168.2.120".parse().unwrap(), 25565));
    thread::sleep(Duration::from_secs(1));
}

fn handle_query(addr: &SocketAddrV4, response: QueryResponse) {
    match response {
        protocols::query::QueryResponse::Partial {
            motd,
            gametype,
            map,
            numplayers,
            maxplayers,
            host,
        } => {
            println!("Got partial stat from {addr}: \n\tMOTD = {motd}\n\tgametype = {gametype}\n\tmap = {map}\n\tnumplayers = {numplayers}\n\tmaxplayers = {maxplayers}\n\thost = {host}");
        }
        protocols::query::QueryResponse::Full {
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

fn get_protocol() -> dyn StatelessProtocol {
    let proto = match CONFIG.protocol {
        config::Protocol::Raknet => RaknetProtocol::new() as dyn StatelessProtocol,
        config::Protocol::Query { fullstat } => {
            MinecraftQueryProtocol::new(handle_query, fullstat) as dyn StatelessProtocol
        }
    };
    proto
}
