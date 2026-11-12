use serde::{Deserialize, Serialize};
use types::{Dyadic, InstanceId, Weight};
/// Exact target eta = numerator / denominator in (0,1].
#[derive(Clone, Debug)]
pub struct Precision {
    pub numerator: Weight,
    pub denominator: Weight,
}
impl Precision {
    pub fn bits(bits: u32) -> Self {
        Self {
            numerator: Weight::from(1),
            denominator: Weight(num_bigint::BigUint::from(1u8) << bits as usize),
        }
    }
}
/// Constant alphabet: initial codes 0..4, second ECHO1 codes 5..7, ECHO2 codes 8..10.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub coordinate: u32,
    pub code: u8,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtMsg {
    pub instance: InstanceId,
    pub round: u32,
    pub entries: Vec<Entry>,
}
#[derive(Clone, Debug)]
pub enum Request {
    Register {
        instance: InstanceId,
        precision: Precision,
    },
    /// Run only these physical-dealer coordinates; omitted outputs are zero.
    /// The caller must agree on coordinates before starting.
    StartSelected {
        instance: InstanceId,
        inputs: Vec<bool>,
        coordinates: Vec<usize>,
    },
    Start {
        instance: InstanceId,
        inputs: Vec<bool>,
    },
}
impl Request {
    pub fn instance(&self) -> InstanceId {
        match self {
            Self::Register { instance, .. }
            | Self::Start { instance, .. }
            | Self::StartSelected { instance, .. } => *instance,
        }
    }
}
#[derive(Clone, Debug)]
pub enum Event {
    Registered {
        instance: InstanceId,
    },
    DeliverVector {
        instance: InstanceId,
        values: Vec<Dyadic>,
    },
    Rejected {
        instance: InstanceId,
        reason: String,
    },
}
