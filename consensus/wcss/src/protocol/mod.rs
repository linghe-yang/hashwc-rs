//! Weighted circuit construction and computational secret sharing.
pub mod circuit;
mod sharing;
pub use circuit::{Circuit, Limits, Op};
pub use sharing::*;
