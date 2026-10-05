use anyhow::{Result, ensure};
use crypto::{Block, hash};
use num_bigint::BigUint;
use sdc_config::Node;
use serde::{Deserialize, Serialize};
use wcss::{Limits, Setup};
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Parameters {
    pub epoch: u64,
    pub coverage_bits: u32,
    pub rounding_bits: u32,
    pub output_bits: u32,
    pub port_stride: Option<u16>,
    /// Selected offline; the runtime only validates and applies this public layout.
    pub bulk_block_bytes: usize,
}
impl Default for Parameters {
    fn default() -> Self {
        Self {
            epoch: 0,
            coverage_bits: 40,
            rounding_bits: 64,
            output_bits: 1,
            port_stride: None,
            bulk_block_bytes: 32,
        }
    }
}
impl Parameters {
    /// Small WRBC headers/declarations keep their own fixed geometry.
    pub const CONTROL_CODING: wavid::CodingParams = wavid::CodingParams { block_bytes: 32 };
    pub fn bulk_coding(&self) -> wavid::CodingParams {
        wavid::CodingParams {
            block_bytes: self.bulk_block_bytes,
        }
    }
    pub fn validate(&self, node: &Node) -> Result<()> {
        node.validate_weighted()?;
        self.bulk_coding().validate()?;
        ensure!(
            node.num_nodes <= sdc_util::weighted::MAX_INSTANCES / 2,
            "WRBC needs two instances per party; maximum 512 parties per invocation"
        );
        ensure!(
            (1..=256).contains(&self.coverage_bits),
            "coverage bits must be in 1..=256"
        );
        ensure!(
            wiawvss::certified::evidence_transport_bound(node.num_nodes, self.bulk_block_bytes)
                <= sdc_util::weighted::MAX_FRAME_BYTES - 256,
            "bulk block makes required fault evidence exceed transport frame limit"
        );
        Self::validate_widths(self.rounding_bits, self.output_bits)?;
        Ok(())
    }
    pub fn validate_widths(rounding_bits: u32, output_bits: u32) -> Result<()> {
        ensure!(
            (1..=252).contains(&rounding_bits) && (1..=252).contains(&output_bits),
            "rounding_bits/output_bits must be in 1..=252"
        );
        ensure!(
            rounding_bits + output_bits < 254,
            "AX p25519 capacity: rounding_bits + output_bits + 1 must be <= 254"
        );
        Ok(())
    }
    pub fn setup(&self, node: &Node) -> Result<Setup> {
        self.validate(node)?;
        Ok(Setup::new(config::policy(node)?, Limits::default())?)
    }
    pub fn range(&self) -> BigUint {
        BigUint::from(1u8) << (self.rounding_bits + self.output_bits + 1) as usize
    }
    pub fn precision(&self, n: usize) -> wbinaa::Precision {
        wbinaa::Precision {
            numerator: sdc_types::Weight::from(1),
            denominator: (self.range() * BigUint::from(n))
                .to_string()
                .parse()
                .expect("decimal integer"),
        }
    }
    pub fn context_id(&self, node: &Node, setup: &Setup) -> Block {
        // Bind the compact-header / striped-storage protocol version.
        hash(
            b"whcc/striped-context/v5",
            &[
                &node.session_id,
                &setup.id(),
                &self.epoch.to_le_bytes(),
                &self.coverage_bits.to_le_bytes(),
                &self.rounding_bits.to_le_bytes(),
                &self.output_bits.to_le_bytes(),
                &(Self::CONTROL_CODING.block_bytes as u64).to_le_bytes(),
                &(self.bulk_block_bytes as u64).to_le_bytes(),
            ],
        )
    }
    pub fn bound_node(&self, node: &Node, setup: &Setup) -> Node {
        let mut node = node.clone();
        node.session_id = self.context_id(&node, setup);
        node
    }
    pub fn sample_message(&self) -> Result<Block> {
        Self::validate_widths(self.rounding_bits, self.output_bits)?;
        let mut b = crypto::random().map_err(|e| anyhow::anyhow!("randomness: {e}"))?;
        let bits = (self.rounding_bits + self.output_bits + 1) as usize;
        let whole = bits / 8;
        let extra = bits % 8;
        b[..32 - whole - usize::from(extra > 0)].fill(0);
        if extra > 0 {
            b[31 - whole] &= (1u8 << extra) - 1;
        }
        Ok(b)
    }
}
