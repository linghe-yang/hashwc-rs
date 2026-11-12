//! Public, deterministic byte minimization; no timing samples or secret inputs.
//!
//! V1 charges every remote initial bundle and every authorized full-retrieval
//! response, even if a receiver finishes early. It also charges WHCC receipts.
//! This is the block-dependent part of a full-service successful-path ledger,
//! NOT a prediction of latency or a minimum over adversarial executions.
use crate::certified::{self, Layout, ModuleEvidenceGeometry};
use anyhow::{Result, ensure};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use wavid::Codec;
use wcss::Setup;

pub const PROFILE: &str = "min-communication-v1";
pub const MIN_BYTES: usize = 32;
pub const MAX_BYTES: usize = 4096;
// Envelope (96), length prefix (4), authenticated ACK (32), ProtMsg (41).
pub const BUNDLE_CHUNK_OVERHEAD: usize = 173;
// Above transport (132), private Packet (25), AEAD envelope (36).
pub const PRIVATE_OVERHEAD: usize = 193;

/// JSON accepts the versioned optimizer name or an explicit legacy integer.
/// The selected value is runtime state: serialize the original request, never
/// silently turn an optimized run into a fixed-parameter ablation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BlockSize {
    fixed: Option<usize>,
    selected: Option<usize>,
}
impl From<usize> for BlockSize {
    fn from(bytes: usize) -> Self {
        Self {
            fixed: Some(bytes),
            selected: None,
        }
    }
}
impl Serialize for BlockSize {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self.fixed {
            Some(b) => s.serialize_u64(b as u64),
            None => s.serialize_str(PROFILE),
        }
    }
}
impl<'de> Deserialize<'de> for BlockSize {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = BlockSize;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "an integer block size or {PROFILE:?}")
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(usize::try_from(v).map_err(E::custom)?.into())
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                if v == PROFILE {
                    Ok(BlockSize::default())
                } else {
                    Err(E::custom("unknown block-size profile"))
                }
            }
        }
        d.deserialize_any(Visitor)
    }
}
impl BlockSize {
    pub fn bytes(self) -> Option<usize> {
        self.fixed.or(self.selected)
    }
    pub fn is_automatic(self) -> bool {
        self.fixed.is_none()
    }
    pub fn validate(self) -> Result<()> {
        if let Some(b) = self.bytes() {
            wavid::CodingParams { block_bytes: b }.validate()?;
        }
        Ok(())
    }
    pub fn select(&mut self, model: &Model) -> Result<Selection> {
        self.validate()?;
        let result = match self.fixed {
            Some(b) => {
                let chosen = model.evaluate(b)?;
                ensure!(
                    chosen.feasible,
                    "block size makes required fault evidence exceed transport frame limit"
                );
                Selection {
                    profile: "fixed",
                    candidates: 1,
                    feasible_candidates: 1,
                    chosen,
                }
            }
            None => model.select()?,
        };
        self.selected = Some(result.chosen.block_bytes);
        Ok(result)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Candidate {
    pub block_bytes: usize,
    pub stripes: usize,
    pub padded_source_bytes: usize,
    pub feasible: bool,
    /// Conservative bound including the private Packet + sealed envelope.
    pub fault_frame_bound: usize,
    pub initial_bundle_bytes: u128,
    pub retrieval_bundle_bytes: u128,
    pub private_receipt_bytes: u128,
    /// Sum of the three terms above. Block-independent control/token traffic,
    /// fault-path traffic, retransmission and TCP/IP headers are excluded.
    pub variable_ledger_bytes: u128,
}
#[derive(Clone, Debug, Serialize)]
pub struct Selection {
    pub profile: &'static str,
    pub candidates: usize,
    pub feasible_candidates: usize,
    pub chosen: Candidate,
}

/// `retrievals[i]` is the number of dealer files party i must retrieve. Sampling
/// uses PUBLIC quotas, not realized random assignments. Public group mode may
/// remove only the self-dealer edges actually served by local dealer reuse.
pub struct Model {
    n: usize,
    m: usize,
    file_bytes: usize,
    counts: Vec<usize>,
    stripe_fixed: Vec<usize>,
    retrievals: Vec<usize>,
    receipts: Option<Vec<Vec<(usize, usize)>>>,
    modules: ModuleEvidenceGeometry,
    frame_limit: usize,
}
impl Model {
    /// All coding/resource checks are inherited from a validated reference
    /// Codec. Its roots, public_id, epoch and block size do not affect the result.
    pub fn new(setup: &Setup, codec: &Codec, retrievals: Vec<usize>, pvr: bool) -> Result<Self> {
        let n = setup.circuit().policy().n();
        ensure!(
            codec.k == n && retrievals.len() == n,
            "block ledger dimensions"
        );
        ensure!(
            retrievals.iter().all(|&r| r <= n),
            "retrieval count exceeds dealer count"
        );
        let expected = if pvr {
            crate::Public::encoded_len(setup)
        } else {
            crate::compact::Public::encoded_len(setup)
        };
        ensure!(codec.file_bytes == expected, "block ledger record layout");
        let b = codec.parameters().block_bytes;
        // Recover the EXACT current bundle-format overhead from Codec rather
        // than maintaining a second implementation of range-frontier proofs.
        let stripe_fixed = (0..n)
            .map(|i| (codec.bundle_bytes(i) - 17) / codec.q - codec.counts[i] * b)
            .collect();
        let layout = Layout::new(setup);
        Ok(Self {
            n,
            m: codec.m,
            file_bytes: expected,
            counts: codec.counts.clone(),
            stripe_fixed,
            retrievals,
            receipts: pvr.then(|| (0..n).map(|i| layout.receipt_ranges(i)).collect()),
            modules: ModuleEvidenceGeometry::new(setup),
            frame_limit: sdc_util::weighted::MAX_FRAME_BYTES - 256,
        })
    }
    pub fn evaluate(&self, b: usize) -> Result<Candidate> {
        wavid::CodingParams { block_bytes: b }.validate()?;
        let q = self.file_bytes.max(1).div_ceil(self.n * b);
        let source =
            56 + b + certified::merkle_proof_bytes(self.m) + certified::merkle_proof_bytes(q);
        let fault_frame_bound = if self.receipts.is_some() {
            // Retain the existing all-file-length conservative coding/legacy
            // bound, and additionally enforce the exact manifest's module bound.
            certified::evidence_transport_bound(self.n, b).max(self.modules.bound(b, source) + 61)
        } else {
            0
        };
        let total: usize = self.retrievals.iter().sum();
        let mut init = 0u128;
        let mut recovery = 0u128;
        for i in 0..self.n {
            let raw = 17 + q * (self.stripe_fixed[i] + self.counts[i] * b);
            let wire = (raw + raw.div_ceil(wavid::CHUNK_BYTES) * BUNDLE_CHUNK_OVERHEAD) as u128;
            init += (self.n - 1) as u128 * wire;
            // Every owner sends to each authorized remote retriever, at most
            // once per dealer. Self transport is excluded, not self-dealer work.
            recovery += (total - self.retrievals[i]) as u128 * wire;
        }
        let receipts = self.receipts.as_ref().map_or(0, |rs| {
            rs.iter()
                .map(|ranges| {
                    let raw = 120 + certified::block_count(b, ranges) * source;
                    (self.n - 1) as u128 * (raw + PRIVATE_OVERHEAD) as u128
                })
                .sum()
        });
        Ok(Candidate {
            block_bytes: b,
            stripes: q,
            padded_source_bytes: q * self.n * b,
            feasible: fault_frame_bound <= self.frame_limit,
            fault_frame_bound,
            initial_bundle_bytes: init,
            retrieval_bundle_bytes: recovery,
            private_receipt_bytes: receipts,
            variable_ledger_bytes: init + recovery + receipts,
        })
    }
    /// Exhaustive finite argmin. Equal costs choose the smaller block size.
    /// No party-count/weight-specific heuristic or alternative algorithm.
    pub fn select(&self) -> Result<Selection> {
        let mut chosen: Option<Candidate> = None;
        let mut feasible_candidates = 0;
        for b in (MIN_BYTES..=MAX_BYTES).step_by(2) {
            let candidate = self.evaluate(b)?;
            if !candidate.feasible {
                continue;
            }
            feasible_candidates += 1;
            if chosen.as_ref().is_none_or(|old| {
                (candidate.variable_ledger_bytes, b) < (old.variable_ledger_bytes, old.block_bytes)
            }) {
                chosen = Some(candidate);
            }
        }
        Ok(Selection {
            profile: PROFILE,
            candidates: (MAX_BYTES - MIN_BYTES) / 2 + 1,
            feasible_candidates,
            chosen: chosen.ok_or_else(|| {
                anyhow::anyhow!(
                    "no block size fits required fault evidence; change the protocol layout"
                )
            })?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn infeasible_layout_is_an_error_without_silent_fallback() {
        let setup = Setup::new_clean(
            types::Policy::new(vec![3u8.into(); 4], 4u8.into()).unwrap(),
            wcss::Limits::default(),
        )
        .unwrap();
        let membership =
            sdc_types::WeightedMembership::new(vec![3u64.into(); 4], 4u64.into()).unwrap();
        let codec = Codec::new(
            &membership,
            sdc_types::InstanceId::new(0, Some(0), 0),
            [0; 32],
            crate::Public::encoded_len(&setup),
        )
        .unwrap();
        let mut model = Model::new(&setup, &codec, vec![4; 4], true).unwrap();
        model.frame_limit = 0;
        assert!(
            model
                .select()
                .unwrap_err()
                .to_string()
                .contains("no block size fits")
        );
        assert!(BlockSize::from(32).select(&model).is_err());
    }
    #[test]
    fn parameter_encoding_is_versioned_and_preserves_numeric_ablations() {
        let auto = BlockSize::default();
        assert!(auto.is_automatic());
        assert_eq!(auto.bytes(), None);
        assert_eq!(
            serde_json::to_string(&auto).unwrap(),
            "\"min-communication-v1\""
        );
        let fixed: BlockSize = serde_json::from_str("1024").unwrap();
        assert_eq!(fixed.bytes(), Some(1024));
        assert_eq!(serde_json::to_string(&fixed).unwrap(), "1024");
        for raw in ["\"auto\"", "\"min-communication-v2\"", "-1", "32.0", "null"] {
            assert!(serde_json::from_str::<BlockSize>(raw).is_err());
        }
    }
}
