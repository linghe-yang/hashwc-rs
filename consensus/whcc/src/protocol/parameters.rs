use anyhow::{Result, ensure};
use crypto::{Block, hash};
use num_bigint::BigUint;
use sdc_config::Node;
use serde::{Deserialize, Serialize};
use wcss::{Limits, Setup};
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecoveryMode {
    #[default]
    Sampled,
    Auto,
    ThreeComplement,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SamplingMode {
    #[default]
    TightV1,
    LegacyV1,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ListBroadcast {
    #[default]
    FixedChunksV1,
    CodedV1,
}
/// Both coin protocols use the same versioned compiler and CSS backend.
pub use wcss::CssProfile as CircuitMode;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Parameters {
    pub epoch: u64,
    pub coverage_bits: u32,
    pub rounding_bits: u32,
    pub output_bits: u32,
    pub port_stride: Option<u16>,
    /// Versioned deterministic optimizer by default; JSON integers pin ablations.
    pub bulk_block_bytes: wiawvss::blocksize::BlockSize,
    pub recovery_mode: RecoveryMode,
    pub sampling_mode: SamplingMode,
    pub list_broadcast: ListBroadcast,
    pub circuit_mode: CircuitMode,
    /// Reuse locally generated AX only when the delivered recovery assignment
    /// includes its dealer. Applies uniformly to sampled and public-group modes.
    pub reuse_local_dealer: bool,
    /// Bracha carries exactly one 32-byte root, never a file or assignment list.
    pub short_root_rbc: bool,
    /// Local computation option; does not change context, messages or authorization.
    pub reuse_verified_material: bool,
    /// Versioned sparse/radix BinAA transport; all peers agree, at most 91 parties.
    pub compact_binaa: bool,
}
impl Default for Parameters {
    fn default() -> Self {
        Self {
            epoch: 0,
            coverage_bits: 40,
            rounding_bits: 44,
            output_bits: 1,
            port_stride: None,
            bulk_block_bytes: Default::default(),
            recovery_mode: RecoveryMode::Sampled,
            sampling_mode: SamplingMode::TightV1,
            list_broadcast: ListBroadcast::FixedChunksV1,
            circuit_mode: CircuitMode::CleanV1,
            reuse_local_dealer: false,
            short_root_rbc: false,
            reuse_verified_material: false,
            compact_binaa: false,
        }
    }
}
impl Parameters {
    /// Small WRBC headers/declarations keep their own fixed geometry.
    pub const CONTROL_CODING: wavid::CodingParams = wavid::CodingParams { block_bytes: 32 };
    pub fn bulk_coding(&self) -> wavid::CodingParams {
        wavid::CodingParams {
            block_bytes: self
                .bulk_block_bytes
                .bytes()
                .expect("resolve block size with Parameters::prepare first"),
        }
    }
    pub fn validate(&self, node: &Node) -> Result<()> {
        node.validate_weighted()?;
        self.bulk_block_bytes.validate()?;
        ensure!(
            !self.compact_binaa || node.num_nodes <= wbinaa::compact::MAX_PARTIES,
            "compact_binaa supports at most 91 parties"
        );
        ensure!(
            node.num_nodes <= sdc_util::weighted::MAX_INSTANCES / 2,
            "WRBC needs two instances per party; maximum 512 parties per invocation"
        );
        ensure!(
            (1..=256).contains(&self.coverage_bits),
            "coverage bits must be in 1..=256"
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
    /// Prepare once, before service registration and before sampling any secrets.
    pub fn prepare(&self, node: &Node) -> Result<(Setup, Self, wiawvss::blocksize::Selection)> {
        let _profile = sdc_util::profile::span("setup.whcc");
        self.validate(node)?;
        let setup = self
            .circuit_mode
            .setup(config::policy(node)?, Limits::default())?;
        let (params, selection) = self.resolve_blocks(node, &setup)?;
        Ok((setup, params, selection))
    }
    pub fn setup(&self, node: &Node) -> Result<Setup> {
        Ok(self.prepare(node)?.0)
    }
    fn resolve_blocks(
        &self,
        node: &Node,
        setup: &Setup,
    ) -> Result<(Self, wiawvss::blocksize::Selection)> {
        let reference = wavid::Codec::with_params(
            &node.weighted_membership()?,
            sdc_types::InstanceId::new(self.epoch, Some(0), 0),
            [0; 32],
            wiawvss::Public::encoded_len(setup),
            Self::CONTROL_CODING,
        )?;
        let sampling = self.sampling(setup)?;
        let plan = self.group_plan(setup)?;
        let list_instances = if plan.is_some() {
            0
        } else {
            match self.list_broadcast {
                ListBroadcast::CodedV1 => node.num_nodes,
                ListBroadcast::FixedChunksV1 => sampling
                    .quotas
                    .iter()
                    .map(|&d| recovery::ranked::Codec::new(node.num_nodes, d).map(|c| c.blocks()))
                    .collect::<Result<Vec<_>>>()?
                    .iter()
                    .sum(),
            }
        };
        ensure!(
            node.num_nodes + list_instances <= sdc_util::weighted::MAX_INSTANCES,
            "root/list chunk instance limit"
        );
        let retrievals = if let Some(plan) = plan {
            plan.lists()
                .iter()
                .enumerate()
                .map(|(i, list)| {
                    list.len() - usize::from(self.reuse_local_dealer && list.contains(&i))
                })
                .collect()
        } else {
            // Public full-service upper bound: a self hit is certain only at
            // quota n. Never deduct an expected self hit from this bound.
            sampling
                .quotas
                .iter()
                .map(|&d| d - usize::from(self.reuse_local_dealer && d == node.num_nodes))
                .collect()
        };
        let model = wiawvss::blocksize::Model::new(setup, &reference, retrievals, true)?;
        let mut params = self.clone();
        let selection = params.bulk_block_bytes.select(&model)?;
        Ok((params, selection))
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
    pub fn sampling(&self, setup: &Setup) -> Result<recovery::Parameters> {
        match self.sampling_mode {
            SamplingMode::TightV1 => {
                recovery::Parameters::new_tight(setup.circuit().policy(), self.coverage_bits)
            }
            SamplingMode::LegacyV1 => {
                recovery::Parameters::new(setup.circuit().policy(), self.coverage_bits)
            }
        }
    }
    pub fn group_plan(&self, setup: &Setup) -> Result<Option<recovery::GroupPlan>> {
        if self.recovery_mode == RecoveryMode::Sampled {
            return Ok(None);
        }
        recovery::GroupPlan::select(
            setup.circuit().policy(),
            self.coverage_bits,
            self.recovery_mode == RecoveryMode::ThreeComplement,
        )
    }
    pub fn context_id(&self, node: &Node, setup: &Setup) -> Block {
        if self.bulk_block_bytes.bytes().is_none() {
            return self
                .resolve_blocks(node, setup)
                .expect("valid public block geometry")
                .0
                .context_id(node, setup);
        }
        let original = self.recovery_context_id(node, setup);
        let original = if self.reuse_local_dealer {
            hash(b"whcc/local-dealer-reuse/v2", &[&original])
        } else {
            original
        };
        let original = if self.sampling_mode == SamplingMode::TightV1 {
            hash(b"whcc/tight-sampling/v1", &[&original])
        } else {
            original
        };
        let original = if self.list_broadcast == ListBroadcast::FixedChunksV1 {
            hash(b"whcc/colex-list-64/v1", &[&original])
        } else {
            original
        };
        let original = if self.bulk_block_bytes.is_automatic() {
            hash(
                b"whcc/block-selection/v1",
                &[&original, wiawvss::blocksize::PROFILE.as_bytes()],
            )
        } else {
            original
        };
        let original = if self.short_root_rbc {
            hash(b"whcc/short-root-header/v1", &[&original])
        } else {
            original
        };
        if self.compact_binaa {
            hash(b"whcc/compact-binaa/v1", &[&original])
        } else {
            original
        }
    }
    fn recovery_context_id(&self, node: &Node, setup: &Setup) -> Block {
        let legacy = self.legacy_context_id(node, setup);
        if self.recovery_mode == RecoveryMode::Sampled && !self.reuse_local_dealer {
            return legacy;
        }
        let plan = self
            .group_plan(setup)
            .expect("validated public recovery plan");
        let digest = plan
            .as_ref()
            .map(recovery::GroupPlan::digest)
            .unwrap_or([0; 32]);
        let mode = match self.recovery_mode {
            RecoveryMode::Sampled => 0,
            RecoveryMode::Auto => 1,
            RecoveryMode::ThreeComplement => 2,
        };
        hash(
            b"whcc/public-recovery-context/v1",
            &[
                &legacy,
                &[
                    mode,
                    u8::from(self.reuse_local_dealer),
                    u8::from(plan.is_some()),
                ],
                &digest,
            ],
        )
    }
    fn legacy_context_id(&self, node: &Node, setup: &Setup) -> Block {
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
                &(self.bulk_coding().block_bytes as u64).to_le_bytes(),
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
