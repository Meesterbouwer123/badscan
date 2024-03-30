use std::{fmt::Display, io};

use once_cell::sync::Lazy;
use serde_derive::Deserialize;
use thiserror::Error;

#[derive(Deserialize, Default)]
pub struct Config {
    pub interface: Option<String>,
    pub scan: ScanConfig,
    pub protocol: Protocol,
    #[serde(default)]
    pub fingerprint: Fingerprint,
}

#[derive(Deserialize, Default)]
pub struct ScanConfig {
    pub seed: i64,
    pub wait_delay: u64,
}

#[derive(Deserialize, Debug)]
#[serde(tag = "t", content = "c")]
pub enum Protocol {
    Query { fullstat: bool },
    Raknet,
    SLP,
}

#[derive(Debug, Deserialize, Default)]
pub enum Fingerprint {
    #[default]
    #[serde(rename = "Nintendo 3DS")]
    Nintendo3DS, // funny :D
}

impl Default for Protocol {
    fn default() -> Self {
        Protocol::Query { fullstat: false }
    }
}

impl Display for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Fingerprint::Nintendo3DS => write!(f, "Nintendo 3DS"),
        }
    }
}

#[derive(Error, Debug)]
enum Error {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Toml(#[from] toml::de::Error),
}

pub static CONFIG: Lazy<Config> =
    Lazy::new(|| Config::get("badscan.toml").expect("Could not read badscan.toml file!"));

impl Config {
    fn get(path: &str) -> Result<Self, Error> {
        let contents = std::fs::read_to_string(path).map_err(|io| Error::Io(io))?;
        let config = toml::from_str(&contents).map_err(|toml| Error::Toml(toml))?;

        Ok(config)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn validate_example() {
        let res = Config::get("badscan.example.toml");
        assert!(res.is_ok());
    }
}
