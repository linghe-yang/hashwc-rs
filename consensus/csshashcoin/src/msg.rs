use serde::Serialize;
#[derive(Clone, Debug)]
pub enum Request {
    Start,
    /// Local benchmark observation; does not enable or cancel protocol work.
    Inspect {
        reply: tokio::sync::mpsc::UnboundedSender<sdc_util::observation::ServiceProgress>,
    },
}
#[derive(Clone, Copy, Debug, Default)]
pub enum Behavior {
    #[default]
    Honest,
    /// Keep input authentication valid but corrupt the full AX commitment.
    InvalidAx,
    InvalidCorrections,
    WithholdRecovery,
    InvalidRecovery,
}
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    Started {
        public_bytes: usize,
    },
    PublicDelivered {
        dealer: usize,
        bytes: usize,
    },
    Shared {
        dealer: usize,
    },
    Gathered {
        dealers: Vec<usize>,
    },
    Frozen {
        numerators: Vec<String>,
        exponents: Vec<u32>,
    },
    TokenReleased {
        dealer: usize,
    },
    Reconstructed {
        dealer: usize,
        rejected: bool,
        value: String,
    },
    Coin {
        epoch: u64,
        value: types::Coin,
    },
    Complete,
    Failed {
        reason: String,
    },
}
pub const PRIVATE: u8 = 0;
pub const RECONSTRUCT: u8 = 1;
#[derive(Debug)]
pub enum Action {
    Rbc(wrbc::Request),
    Ra(wra::Request),
    Gather(wgather::Request),
    BinAa(wbinaa::Request),
    Private {
        recipient: usize,
        packet: network::Packet,
    },
    Recovery {
        recipient: usize,
        packet: network::Packet,
    },
}
