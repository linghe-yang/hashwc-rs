//! Common coin state and protocol logic.
pub mod adversary;
pub use adversary::Behavior;
pub mod aggregate;
pub mod parameters;
mod recovery;
mod sharing;
pub mod state;
pub use parameters::Parameters;
pub use state::State;

#[cfg(test)]
mod tests;
