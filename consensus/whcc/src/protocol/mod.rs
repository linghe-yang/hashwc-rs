//! Common coin state and protocol logic.
pub mod adversary;
pub use adversary::Behavior;
pub mod aggregate;
mod local;
mod observation;
pub mod parameters;
mod recovery;
mod sharing;
pub mod state;
mod work;
pub use parameters::{CircuitMode, Parameters, RecoveryMode};
pub use state::State;

#[cfg(test)]
mod tests;
