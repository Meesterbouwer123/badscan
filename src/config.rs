use once_cell::sync::Lazy;
use serde_derive::Deserialize;

#[derive(Deserialize, Default)]
pub struct Config {
    pub send_packets: bool,
    pub interface: Option<String>,
}

pub static CONFIG: Lazy<Config> = Lazy::new(|| Config::get());
const FILE_NAME: &str = "config.toml";

impl Config {
    fn get() -> Self {
        let contents = std::fs::read_to_string(FILE_NAME)
            .unwrap_or_else(|_| panic!("Could not read {FILE_NAME}"));
        let config = toml::from_str(&contents)
            .unwrap_or_else(|err| panic!("Could not read {FILE_NAME}: {err}"));

        config
    }
}
