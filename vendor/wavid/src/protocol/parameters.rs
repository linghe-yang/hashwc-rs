use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

/// Public coding layout, fixed before registering an instance and bound into its root.
/// This does not configure TCP frames, worker batches, or local caches.
/// Node::block_size belongs to legacy protocols and does not set this value.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CodingParams {
    /// Bytes in one systematic source block / encoded coordinate.
    /// Choose an even value in 32..=4096, large enough for the application's short
    /// authenticated fields. 32 is the conservative default; 64/128/256 can reduce
    /// directory and path overhead. Larger blocks also enlarge fault certificates
    /// (k blocks) and semantic openings. Keep b = Theta(lambda + log n) when relying
    /// on the paper's bounds; the resource cap alone does not guarantee that bound.
    pub block_bytes: usize,
}
impl Default for CodingParams {
    fn default() -> Self {
        Self {
            block_bytes: super::BLOCK_BYTES,
        }
    }
}
impl CodingParams {
    pub fn validate(self) -> Result<()> {
        ensure!(
            (32..=4096).contains(&self.block_bytes) && self.block_bytes % 2 == 0,
            "block_bytes must be even and in 32..=4096"
        );
        Ok(())
    }
}
