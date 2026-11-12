//! HashRand with virtual Shamir shares and physical weighted control protocols.
//! This is a static-adversary research baseline, not a claim of adaptive security.
pub mod bwavss;
mod context;
pub mod msg;
pub mod parameters;
pub mod protocol;
mod short_rbc;
pub use context::{Context, Handle};
pub use msg::{Behavior, Event, Request};
pub use parameters::Parameters;
pub use protocol::State;
