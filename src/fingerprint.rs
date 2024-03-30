use pnet::packet::tcp::{TcpFlags, TcpOption};

use crate::tcp::template::TcpTemplate;

// this entire part is inspired by https://github.com/mat-1/matscan/pull/5
// <3

#[derive(Debug, Clone, Default)]
pub struct Fingerprint {
    pub ittl: u8, // initial time to live
    pub mss: u16,
    pub window: u16,
    pub options: Vec<TcpOption>,
    syn_template: TcpTemplate,
}

impl Fingerprint {
    pub fn get_syn(&self) -> TcpTemplate {
        self.syn_template.clone()
    }

    pub fn get_ack(&self) -> TcpTemplate {
        TcpTemplate::new(TcpFlags::ACK, self.window, self.options.clone())
    }

    pub fn get_rst(&self) -> TcpTemplate {
        TcpTemplate::new(TcpFlags::RST, self.window, self.options.clone())
    }

    pub fn get_psh(&self) -> TcpTemplate {
        TcpTemplate::new(
            TcpFlags::PSH | TcpFlags::ACK,
            self.window,
            self.options.clone(),
        )
    }

    fn new(ittl: u8, mss: u16, window: u16, options: Vec<TcpOption>) -> Self {
        let syn_template = TcpTemplate::new(TcpFlags::SYN, window, options.clone());
        Self {
            ittl,
            mss,
            window,
            options,
            syn_template,
        }
    }

    // functions for getting pre-built fingerprints
    pub fn nintendo_3ds() -> Self {
        // from the p0f fingerprint *:64:0:1360:32768,0:mss,nop,nop,sok:df,id+:0
        Self::new(
            64,
            1360,
            32768,
            vec![
                TcpOption::mss(1360),
                TcpOption::nop(),
                TcpOption::nop(),
                TcpOption::sack_perm(),
            ],
        )
    }
}
