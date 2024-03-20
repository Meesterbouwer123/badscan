use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    net::SocketAddrV4,
};

use crate::config::CONFIG;

pub fn cookie(addr: &SocketAddrV4) -> u32 {
    let mut hasher = DefaultHasher::new();
    //TODO: add secret to avoid people faking requests
    (*addr.ip(), addr.port(), CONFIG.scankey).hash(&mut hasher);
    hasher.finish() as u32
}
