//! Weighted common coin with independent local recovery sampling.
pub mod context;
pub mod msg;
pub mod protocol;
pub mod root_rbc;
pub use context::{Context, Handle};
pub use msg::{Event, Request};
pub use protocol::*;
pub use types::Coin;
