use anyhow::{Result, ensure};
use config::Node;
use crypto::Block;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use wcss::{Limits, Setup};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Parameters {
    pub epoch: u64,
    pub rounding_bits: u32,
    pub output_bits: u32,
    pub port_stride: Option<u16>,
    /// Geometry of the existing weighted RBC, not the PVR stripe layout.
    pub rbc_block_bytes: wiawvss::blocksize::BlockSize,
    /// Same explicit session-wide profile as WHCC; never chosen per input.
    pub circuit_mode: wcss::CssProfile,
    /// Retain the dealer's canonical public file; deliver only after normal RBC
    /// completion. CSS reconstruction and Freeze gating are unchanged.
    pub reuse_local_dealer: bool,
    /// Shared BinAA wire encoding; does not change the AA transition rules.
    pub compact_binaa: bool,
}
impl Default for Parameters {
    fn default() -> Self {
        Self {
            epoch: 0,
            rounding_bits: 44,
            output_bits: 1,
            port_stride: None,
            rbc_block_bytes: Default::default(),
            circuit_mode: wcss::CssProfile::CleanV1,
            reuse_local_dealer: false,
            compact_binaa: false,
        }
    }
}
impl Parameters {
    fn aggregation_parameters(&self) -> whcc::Parameters {
        whcc::Parameters {
            rounding_bits: self.rounding_bits,
            output_bits: self.output_bits,
            ..whcc::Parameters::default()
        }
    }
    pub fn validate(&self, node: &Node) -> Result<()> {
        node.validate_weighted()?;
        ensure!(
            (2..=sdc_util::weighted::MAX_INSTANCES).contains(&node.num_nodes),
            "party limit"
        );
        whcc::Parameters::validate_widths(self.rounding_bits, self.output_bits)?;
        ensure!(
            !self.compact_binaa || node.num_nodes <= wbinaa::compact::MAX_PARTIES,
            "compact_binaa supports at most 91 parties"
        );
        self.rbc_block_bytes.validate()?;
        config::Ports::new(node, self.port_stride)?;
        Ok(())
    }
    pub fn coding(&self) -> wavid::CodingParams {
        wavid::CodingParams {
            block_bytes: self
                .rbc_block_bytes
                .bytes()
                .expect("resolve block size with Parameters::prepare first"),
        }
    }
    pub fn prepare(&self, node: &Node) -> Result<(Setup, Self, wiawvss::blocksize::Selection)> {
        let _profile = sdc_util::profile::span("setup.csshashcoin");
        self.validate(node)?;
        let setup = self
            .circuit_mode
            .setup(config::policy(node)?, Limits::default())?;
        let codec = wavid::Codec::with_params(
            &node.weighted_membership()?,
            sdc_types::InstanceId::new(self.epoch, Some(0), 0),
            [0; 32],
            wiawvss::compact::Public::encoded_len(&setup),
            wavid::CodingParams::default(),
        )?;
        let model = wiawvss::blocksize::Model::new(
            &setup,
            &codec,
            vec![node.num_nodes - usize::from(self.reuse_local_dealer); node.num_nodes],
            false,
        )?;
        let mut params = self.clone();
        let selection = params.rbc_block_bytes.select(&model)?;
        Ok((setup, params, selection))
    }
    pub fn setup(&self, node: &Node) -> Result<Setup> {
        Ok(self.prepare(node)?.0)
    }
    pub fn range(&self) -> BigUint {
        self.aggregation_parameters().range()
    }
    pub fn precision(&self, n: usize) -> wbinaa::Precision {
        self.aggregation_parameters().precision(n)
    }
    pub fn sample_message(&self) -> Result<Block> {
        self.aggregation_parameters().sample_message()
    }
    pub fn bound_node(&self, node: &Node) -> Node {
        if self.rbc_block_bytes.bytes().is_none() {
            return self
                .prepare(node)
                .expect("valid public block geometry")
                .1
                .bound_node(node);
        }
        let mut bound = node.clone();
        bound.session_id = crypto::hash(
            b"csshashcoin/compact-full-rbc/v1",
            &[
                &node.weighted_public_id("csshashcoin"),
                &serde_json::to_vec(self).unwrap(),
            ],
        );
        if self.rbc_block_bytes.is_automatic() {
            bound.session_id = crypto::hash(
                b"csshashcoin/block-selection/v1",
                &[
                    &bound.session_id,
                    wiawvss::blocksize::PROFILE.as_bytes(),
                    &(self.coding().block_bytes as u64).to_le_bytes(),
                ],
            );
        }
        bound
    }
}
