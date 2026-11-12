//! Weighted circuit construction and computational secret sharing.
pub mod boundary;
pub mod circuit;
mod sharing;
pub use circuit::{CandidateSize, CandidateStatus, Circuit, Compilation, Construction, Limits, Op};
pub use sharing::*;

/// A session-wide compiler/backend choice, never selected from the input size.
/// Legacy modes remain available for explicit historical comparisons.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CssProfile {
    Legacy,
    OptimizedV1,
    #[default]
    CleanV1,
}
impl CssProfile {
    pub fn setup(self, policy: types::Policy, limits: Limits) -> types::Result<Setup> {
        match self {
            Self::Legacy => Setup::new(policy, limits),
            Self::OptimizedV1 => Setup::new_optimized(policy, limits),
            Self::CleanV1 => Setup::new_clean(policy, limits),
        }
    }
}

/// Circuit CSS without the wire digests used only by certified local recovery.
pub mod compact;
