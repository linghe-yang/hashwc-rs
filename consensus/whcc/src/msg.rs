use network::Packet;
use sdc_types::Dyadic;
#[derive(Clone, Debug)]
pub enum Request {
    Start,
    /// Local benchmark observation; never serialized onto protocol channels.
    Inspect {
        reply: tokio::sync::mpsc::UnboundedSender<sdc_util::observation::ServiceProgress>,
    },
}
#[derive(Clone, Debug, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    Shared {
        dealer: usize,
    },
    AdversarialTerminal {
        dealer: usize,
        recipients: usize,
    },
    TerminalChecked {
        dealer: usize,
        sender: usize,
        decoded: bool,
        accepted: bool,
    },
    Gathered {
        dealers: Vec<usize>,
    },
    Frozen {
        coefficients: Vec<Dyadic>,
    },
    Terminal {
        dealer: usize,
        rejected: bool,
    },
    Coin {
        epoch: u64,
        value: types::Coin,
    },
    Failed {
        reason: String,
    },
}
#[derive(Debug)]
pub enum Action {
    Rbc(wrbc::Request),
    RootRbc(crate::root_rbc::Request),
    Avid(wavid::Request),
    Ra(wra::Request),
    Gather(wgather::Request),
    BinAa(wbinaa::Request),
    Private { recipient: usize, packet: Packet },
    Recovery { recipient: usize, packet: Packet },
}
pub const PRIVATE_TOKEN: u8 = 0;
pub const RECOVERY_TOKEN: u8 = 1;
pub const TERMINAL: u8 = 2;
