//! Fixed 32 B roots and 64 B list chunks use the same weighted Bracha algorithm.
pub mod chunks;
mod service;
mod state;
use sdc_types::InstanceId;
use serde::{Deserialize, Serialize};
pub(crate) use service::spawn;
pub use state::State;
pub type Root = [u8; 32];
#[derive(Clone, Debug)]
pub struct Request {
    pub instance: InstanceId,
    pub root: Root,
}
#[derive(Clone, Debug)]
pub struct Event {
    pub instance: InstanceId,
    pub root: Root,
}
#[derive(Clone, Debug)]
pub enum ServiceEvent {
    Root(Event),
    List(chunks::Event),
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    pub instance: InstanceId,
    pub kind: Kind,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Kind {
    Init(Root),
    Echo(Root),
    Ready(Root),
    // Transport multiplexing only; this variant NEVER enters Bracha voting.
    Coded(Box<wavid::Kind>),
    ChunkInit(recovery::ranked::Block),
    ChunkEcho(recovery::ranked::Block),
    ChunkReady(recovery::ranked::Block),
}
#[cfg(test)]
mod chunk_tests;
#[cfg(test)]
mod tests;

/// Fixed formats only; no variable-length payload enters Bracha voting.
pub trait Payload: Copy + Ord {
    type Delivery;
    fn valid_slot(slot: u64) -> bool;
    fn kind(self, phase: usize) -> Kind;
    fn extract(kind: Kind) -> Option<(usize, Self)>;
    fn event(self, instance: InstanceId) -> Self::Delivery;
}
impl Payload for Root {
    type Delivery = Event;
    fn valid_slot(slot: u64) -> bool {
        slot == 0
    }
    fn kind(self, p: usize) -> Kind {
        match p {
            0 => Kind::Init(self),
            1 => Kind::Echo(self),
            _ => Kind::Ready(self),
        }
    }
    fn extract(kind: Kind) -> Option<(usize, Self)> {
        match kind {
            Kind::Init(x) => Some((0, x)),
            Kind::Echo(x) => Some((1, x)),
            Kind::Ready(x) => Some((2, x)),
            _ => None,
        }
    }
    fn event(self, instance: InstanceId) -> Event {
        Event {
            instance,
            root: self,
        }
    }
}
#[derive(Clone, Debug)]
pub struct ChunkEvent {
    pub instance: InstanceId,
    pub block: recovery::ranked::Block,
}
impl Payload for recovery::ranked::Block {
    type Delivery = ChunkEvent;
    fn valid_slot(slot: u64) -> bool {
        slot >= 1
    }
    fn kind(self, p: usize) -> Kind {
        match p {
            0 => Kind::ChunkInit(self),
            1 => Kind::ChunkEcho(self),
            _ => Kind::ChunkReady(self),
        }
    }
    fn extract(kind: Kind) -> Option<(usize, Self)> {
        match kind {
            Kind::ChunkInit(x) => Some((0, x)),
            Kind::ChunkEcho(x) => Some((1, x)),
            Kind::ChunkReady(x) => Some((2, x)),
            _ => None,
        }
    }
    fn event(self, instance: InstanceId) -> ChunkEvent {
        ChunkEvent {
            instance,
            block: self,
        }
    }
}
