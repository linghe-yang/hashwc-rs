use types::InstanceId;
pub use wavid::ProtMsg;
#[derive(Clone, Debug)]
pub enum Request {
    Register {
        instance: InstanceId,
        file_bytes: usize,
        /// Public layout; identical at every node, bound into the WAVID root.
        coding: wavid::CodingParams,
    },
    Broadcast {
        instance: InstanceId,
        data: Vec<u8>,
    },
}
impl Request {
    pub fn instance(&self) -> InstanceId {
        match self {
            Self::Register { instance, .. } | Self::Broadcast { instance, .. } => *instance,
        }
    }
}
#[derive(Clone, Debug)]
pub enum Event {
    Registered {
        instance: InstanceId,
    },
    Deliver {
        instance: InstanceId,
        data: wavid::ValidatedFile,
    },
    Invalid {
        instance: InstanceId,
        proof: wavid::StorageFault,
    },
    Rejected {
        instance: InstanceId,
        reason: String,
    },
}
