//! Weighted common coin with independent local recovery sampling.
pub mod context;
pub mod msg;
mod process;
pub mod protocol;
pub use context::{Context, Handle};
pub use msg::{Event, Request};
pub use protocol::*;
