//! Single-invocation CSS-HashCoin: full CSS+AX RBC and local recovery by every party.
//! Static corruption B < T, 3(T-1) < W for integer weights. No batching, AnyTrust, or recovery sampling.
mod context;
pub mod msg;
pub mod parameters;
pub mod protocol;
pub use context::{Context, Handle};
pub use msg::{Behavior, Event, Request};
pub use parameters::Parameters;
pub use protocol::State;
