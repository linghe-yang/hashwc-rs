use network::Packet;
use sdc_types::Dyadic;
#[derive(Clone, Debug)]
pub enum Request {
    Start,
}
#[derive(Clone, Debug)]
pub enum Event {
    Shared { dealer: usize },
    Gathered { dealers: Vec<usize> },
    Frozen { coefficients: Vec<Dyadic> },
    Terminal { dealer: usize, rejected: bool },
    Coin { epoch: u64, value: types::Coin },
    Failed { reason: String },
}
#[derive(Debug)]
pub enum Action {
    Rbc(wrbc::Request),
    Ra(wra::Request),
    Gather(wgather::Request),
    BinAa(wbinaa::Request),
    Private { recipient: usize, packet: Packet },
    Recovery { recipient: usize, packet: Packet },
}
pub const PRIVATE_TOKEN: u8 = 0;
pub const RECOVERY_TOKEN: u8 = 1;
pub const TERMINAL: u8 = 2;
