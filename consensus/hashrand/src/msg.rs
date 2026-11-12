use crate::bwavss::Bundle;
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug)]
pub enum Request {
    Start,
    /// Read-only observer request, never a protocol stopping condition.
    Inspect {
        reply: tokio::sync::mpsc::UnboundedSender<sdc_util::observation::ServiceProgress>,
    },
}
#[derive(Clone, Copy, Debug, Default)]
pub enum Behavior {
    #[default]
    Honest,
    /// Commit to a non-codeword while sending valid authentication proofs.
    InvalidPolynomial,
    WithholdRecovery,
}
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    Shared {
        batch: usize,
        dealer: usize,
    },
    Gathered {
        batch: usize,
        dealers: Vec<usize>,
    },
    SeedRelease {
        target_batch: usize,
        source_batch: usize,
        source_slot: usize,
    },
    Committee {
        batch: usize,
        sampled: bool,
        dealers: Vec<usize>,
    },
    Frozen {
        batch: usize,
    },
    Reconstructed {
        batch: usize,
        dealer: usize,
        slot: usize,
        rejected: bool,
    },
    SeedOpened {
        target_batch: usize,
        value: types::Coin,
    },
    Beacon {
        batch: usize,
        index: usize,
        value: types::Coin,
    },
    Complete,
    Failed {
        reason: String,
    },
}
#[derive(Clone, Serialize, Deserialize)]
pub struct SharePacket {
    pub slot: usize,
    pub bundle: Bundle,
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
