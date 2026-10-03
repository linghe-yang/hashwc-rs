//! Messages, outgoing actions, and public events for wiAwVSS.
use crate::{PrivateShare, Recovery};

#[derive(Clone, Debug)]
pub enum Message {
    Public(wrbc::ProtMsg),
    Completion(wra::ProtMsg),
    Private(PrivateShare),
    Open(PrivateShare),
}
#[derive(Clone, Debug)]
pub struct Action {
    pub recipient: usize,
    pub message: Message,
}
#[derive(Debug)]
pub enum Event {
    Shared,
    Reconstructed(Recovery),
    Bottom,
    InvalidPublic,
}
