use crate::bwavss::Layout;
use anyhow::{Result, ensure};
use config::Node;
use crypto::Block;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Parameters {
    pub epoch: u64,
    /// External beacon words per batch. One batch of size one is a standalone coin.
    pub batch_size: usize,
    pub batches: usize,
    pub rounding_bits: u32,
    pub output_bits: u32,
    pub sampling_bits: u32,
    pub port_stride: Option<u16>,
    pub max_virtual_shares: usize,
    pub compact_binaa: bool,
    pub reuse_local_dealer: bool,
}
impl Default for Parameters {
    fn default() -> Self {
        Self {
            epoch: 0,
            batch_size: 1,
            batches: 1,
            rounding_bits: 44,
            output_bits: 1,
            sampling_bits: 40,
            port_stride: None,
            max_virtual_shares: 4096,
            compact_binaa: false,
            reuse_local_dealer: false,
        }
    }
}
impl Parameters {
    pub const SEED_BITS: u32 = 128;
    pub fn checkpoint(&self, batch: usize, n: usize) -> bool {
        batch.is_multiple_of(n)
    }
    pub fn reserved(&self, batch: usize, n: usize) -> usize {
        if self.checkpoint(batch, n) {
            (self.batches - batch - 1).min(n - 1)
        } else {
            0
        }
    }
    pub fn slots(&self, batch: usize, n: usize) -> usize {
        self.batch_size + self.reserved(batch, n)
    }
    /// Each subsequent batch uses one still-unopened slot from a preceding full-committee checkpoint.
    pub fn seed_source(&self, batch: usize, n: usize) -> Option<(usize, usize)> {
        if self.checkpoint(batch, n) {
            None
        } else {
            Some((batch / n * n, self.batch_size + batch % n - 1))
        }
    }
    pub fn output_width(&self, slot: usize) -> u32 {
        if slot < self.batch_size {
            self.output_bits
        } else {
            Self::SEED_BITS
        }
    }
    pub fn contribution_width(&self, slot: usize) -> u32 {
        self.rounding_bits + self.output_width(slot) + 1
    }
    pub fn precision(&self, n: usize) -> wbinaa::Precision {
        let bits = self
            .output_bits
            .max(if self.batches > 1 { Self::SEED_BITS } else { 1 });
        let denominator = (BigUint::from(n) << (self.rounding_bits + bits + 1)).to_string();
        wbinaa::Precision {
            numerator: sdc_types::Weight::from(1),
            denominator: denominator.parse().unwrap(),
        }
    }
    pub fn layout(&self, node: &Node) -> Result<Layout> {
        node.validate_weighted()?;
        let m = node.weighted_membership()?;
        Layout::new(
            &m.weights
                .iter()
                .map(|w| BigUint::from_bytes_be(&w.0.to_bytes_be()))
                .collect::<Vec<_>>(),
            &BigUint::from_bytes_be(&m.threshold.to_bytes_be()),
            self.max_virtual_shares,
        )
    }
    pub fn validate(&self, node: &Node) -> Result<()> {
        self.layout(node)?;
        ensure!(
            !self.compact_binaa || node.num_nodes <= wbinaa::compact::MAX_PARTIES,
            "compact_binaa supports at most 91 parties"
        );
        ensure!(
            (1..=1024).contains(&self.batch_size) && (1..=64).contains(&self.batches),
            "batch resource limits"
        );
        ensure!(
            (1..=128).contains(&self.sampling_bits),
            "sampling_bits in 1..=128"
        );
        ensure!(
            self.epoch.checked_add(self.batches as u64).is_some(),
            "epoch overflow"
        );
        ensure!(
            node.num_nodes >= 2
                && self.batches * (node.num_nodes + 1) <= sdc_util::weighted::MAX_INSTANCES,
            "instance limit"
        );
        whcc::Parameters::validate_widths(self.rounding_bits, self.output_bits)?;
        if self.batches > 1 {
            whcc::Parameters::validate_widths(self.rounding_bits, Self::SEED_BITS)?;
        }
        let layout = self.layout(node)?;
        let cells: usize = (0..self.batches)
            .map(|b| self.slots(b, node.num_nodes))
            .sum();
        ensure!(
            cells
                .checked_mul(layout.total)
                .and_then(|x| x.checked_mul(node.num_nodes))
                .is_some_and(|x| x <= 8_000_000),
            "live sharing cell resource limit"
        );
        let max_bundle = 64
            + layout.ranges.iter().map(|r| r.len()).max().unwrap() * 114
            + 64 * (layout.total.next_power_of_two().trailing_zeros() as usize + 1);
        ensure!(
            max_bundle < sdc_util::weighted::MAX_FRAME_BYTES - 512,
            "share bundle exceeds frame limit"
        );
        config::Ports::new(node, self.port_stride)?;
        Ok(())
    }
    pub fn bound_node(&self, node: &Node) -> Node {
        let mut result = node.clone();
        result.session_id = crypto::hash(
            b"hashrand-vs/context/v1",
            &[
                &node.weighted_public_id("hashrand-vs"),
                &serde_json::to_vec(self).unwrap(),
            ],
        );
        result
    }
    pub fn context(&self, node: &Node, batch: usize, dealer: usize) -> Block {
        crypto::hash(
            b"hashrand-vs/dealer/v1",
            &[
                &self.bound_node(node).session_id,
                &(batch as u64).to_le_bytes(),
                &(dealer as u64).to_le_bytes(),
            ],
        )
    }
}
