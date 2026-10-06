use crypto::{aes_hash::Proof, hash::Hash};
use serde::{Deserialize, Serialize};
use types::{InstanceId, Replica};
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Fragment {
    pub index: usize,
    pub data: Vec<u8>,
    pub proof: Proof,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Bundle {
    pub directory: Vec<Hash>,
    pub stripes: Vec<Vec<Fragment>>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Kind {
    Init { index: u32, bytes: Vec<u8> },
    Ack(Hash),
    Ready(Hash),
    Request(Hash),
    Data { index: u32, bytes: Vec<u8> },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtMsg {
    pub instance: InstanceId,
    pub kind: Kind,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionMode {
    Storage,
    External,
}
/// External completion is used when the application combines storage with private-share receipts via WRA.
#[derive(Clone, Debug)]
pub struct Descriptor {
    /// Public immutable coding geometry; must agree at all nodes before dispersal.
    pub coding: crate::CodingParams,
    /// Exact canonical source length, excluding WAVID padding; 0..=MAX_FILE_BYTES.
    pub file_bytes: usize,
    /// Authenticated directory root; External mode permits a later Pin.
    pub root: Option<Hash>,
    /// Authorized physical IDs; append later via Authorize, never revoke.
    pub retrievers: Vec<Replica>,
    /// Storage for standalone use; External for application-validated joint completion.
    pub completion: CompletionMode,
}
#[derive(Clone, Debug)]
pub enum Request {
    Register {
        instance: InstanceId,
        descriptor: Descriptor,
    },
    Disperse {
        instance: InstanceId,
        data: Vec<u8>,
    },
    /// Reuse a locally prepared canonical encoding; not a wire message.
    DisperseCached {
        instance: InstanceId,
        prepared: crate::Dispersal,
    },
    Retrieve {
        instance: InstanceId,
    },
    Authorize {
        instance: InstanceId,
        retrievers: Vec<Replica>,
    },
    /// Pin a root obtained from the application after an early storage packet.
    Pin {
        instance: InstanceId,
        root: Hash,
    },
    Complete {
        instance: InstanceId,
        root: Hash,
    },
}
impl Request {
    pub fn instance(&self) -> InstanceId {
        match self {
            Self::Register { instance, .. }
            | Self::Disperse { instance, .. }
            | Self::DisperseCached { instance, .. }
            | Self::Retrieve { instance }
            | Self::Authorize { instance, .. }
            | Self::Complete { instance, .. }
            | Self::Pin { instance, .. } => *instance,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SourceOpening {
    pub stripe: usize,
    pub root: Hash,
    pub directory_proof: Proof,
    pub fragment: Fragment,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StripeWitness {
    pub stripe: usize,
    pub root: Hash,
    pub directory_proof: Proof,
    pub fragments: Vec<Fragment>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum StorageFault {
    Coding(StripeWitness),
    Padding(SourceOpening),
}
#[derive(Clone, Debug)]
pub enum Retrieval {
    File(crate::ValidatedFile),
    Invalid(StorageFault),
}
#[derive(Clone, Debug)]
pub enum Event {
    Registered {
        instance: InstanceId,
    },
    Stored {
        instance: InstanceId,
        root: Hash,
    },
    Complete {
        instance: InstanceId,
        root: Hash,
    },
    Result {
        instance: InstanceId,
        result: Retrieval,
    },
    Rejected {
        instance: InstanceId,
        reason: String,
    },
}
