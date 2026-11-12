//! Batched hash-based weak VSS (HashRand Algorithm 2).
//! Only Shamir evaluation positions are virtualized. Physical parties own
//! contiguous ticket ranges, authenticated with the existing range multiproof.
use anyhow::{Result, ensure};
use crypto::Block;
use num_bigint::BigUint;
use num_traits::{One, ToPrimitive, Zero};
use sdc_crypto::weighted_merkle::{IndexedTree, verify_range};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, ops::Range};

#[derive(Clone, Debug)]
pub struct Layout {
    pub ranges: Vec<Range<usize>>,
    pub total: usize,
    pub threshold: usize,
}
impl Layout {
    pub fn new(weights: &[BigUint], threshold: &BigUint, max: usize) -> Result<Self> {
        let total: BigUint = weights.iter().sum();
        ensure!(
            !weights.is_empty() && weights.iter().all(|w| !w.is_zero()),
            "positive weights required"
        );
        ensure!(
            !threshold.is_zero() && (threshold - BigUint::from(1u8)) * 3u8 < total,
            "require T > 0 and 3(T-1) < W"
        );
        let total = total
            .to_usize()
            .filter(|&w| w <= max && w <= 1 << 24)
            .ok_or_else(|| anyhow::anyhow!("virtual share resource limit: raw W exceeds {max}"))?;
        let threshold = threshold.to_usize().unwrap();
        let mut start = 0;
        let ranges = weights
            .iter()
            .map(|w| {
                let end = start + w.to_usize().unwrap();
                let range = start..end;
                start = end;
                range
            })
            .collect();
        Ok(Self {
            ranges,
            total,
            threshold,
        })
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Share {
    pub value: Vec<u8>,
    pub blind: Vec<u8>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Bundle {
    pub shares: Vec<Share>,
    pub proof: Vec<Block>,
}
impl std::fmt::Debug for Bundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bundle")
            .field("shares", &self.shares.len())
            .field("proof_hashes", &self.proof.len())
            .finish()
    }
}
/// Public prime fields. The 521-bit blinding field exceeds twice the hash width.
pub struct Field {
    modulus: BigUint,
    modulus_bytes: Vec<u8>,
    bytes: usize,
    inverses: Vec<BigUint>,
}
impl Field {
    fn new(bits: usize, subtract: u8, max_difference: usize) -> Self {
        let modulus = (BigUint::one() << bits) - BigUint::from(subtract);
        let mut inverses = vec![BigUint::zero(); max_difference + 1];
        inverses[1] = BigUint::one();
        for i in 2..=max_difference {
            let x = BigUint::from(i);
            let remainder = (&modulus % &x).to_usize().unwrap();
            inverses[i] = &modulus - ((&modulus / &x) * &inverses[remainder]) % &modulus;
        }
        Self {
            modulus_bytes: modulus.to_bytes_be(),
            modulus,
            bytes: bits.div_ceil(8),
            inverses,
        }
    }
    fn decode(&self, bytes: &[u8]) -> Option<BigUint> {
        self.canonical(bytes).then(|| BigUint::from_bytes_be(bytes))
    }
    fn canonical(&self, bytes: &[u8]) -> bool {
        bytes.len() == self.bytes && bytes < self.modulus_bytes.as_slice()
    }
    fn encode(&self, value: &BigUint) -> Vec<u8> {
        let raw = value.to_bytes_be();
        let mut bytes = vec![0; self.bytes];
        bytes[self.bytes - raw.len()..].copy_from_slice(&raw);
        bytes
    }
    fn random(&self) -> Result<BigUint> {
        loop {
            let mut bytes = vec![0; self.bytes];
            getrandom::fill(&mut bytes).map_err(|e| anyhow::anyhow!("randomness: {e}"))?;
            let spare = self.bytes * 8 - self.modulus.bits() as usize;
            bytes[0] &= 255u8 >> spare;
            let v = BigUint::from_bytes_be(&bytes);
            if v < self.modulus {
                return Ok(v);
            }
        }
    }
    fn polynomial(&self, secret: BigUint, threshold: usize) -> Result<Vec<BigUint>> {
        let mut p = Vec::with_capacity(threshold);
        p.push(secret);
        // A bounded CSPRNG buffer avoids one OS request per coefficient. Each
        // field element still uses independent bytes and unbiased rejection.
        let mut buffer = [0u8; 2112];
        let spare = self.bytes * 8 - self.modulus.bits() as usize;
        while p.len() < threshold {
            let count = (threshold - p.len()).min(buffer.len() / self.bytes);
            let bytes = &mut buffer[..count * self.bytes];
            getrandom::fill(bytes).map_err(|e| anyhow::anyhow!("randomness: {e}"))?;
            for raw in bytes.chunks_exact_mut(self.bytes) {
                raw[0] &= 255u8 >> spare;
                let v = BigUint::from_bytes_be(raw);
                p.push(if v < self.modulus { v } else { self.random()? });
            }
        }
        Ok(p)
    }
    fn evaluate(&self, p: &[BigUint], x: usize) -> BigUint {
        p.iter()
            .rev()
            .fold(BigUint::zero(), |y, a| (y * x + a) % &self.modulus)
    }
    fn interpolate(&self, points: &[(usize, BigUint)]) -> Polynomial {
        let xs: Vec<_> = points.iter().map(|p| p.0).collect();
        let mut coefficients: Vec<_> = points.iter().map(|p| p.1.clone()).collect();
        for order in 1..points.len() {
            for i in (order..points.len()).rev() {
                let delta =
                    (&coefficients[i] + &self.modulus - &coefficients[i - 1]) % &self.modulus;
                coefficients[i] = delta * &self.inverses[xs[i] - xs[i - order]] % &self.modulus;
            }
        }
        Polynomial { xs, coefficients }
    }
}
struct Polynomial {
    xs: Vec<usize>,
    coefficients: Vec<BigUint>,
}
impl Polynomial {
    fn at(&self, field: &Field, x: usize) -> BigUint {
        let mut y = self.coefficients.last().unwrap().clone();
        for i in (0..self.coefficients.len() - 1).rev() {
            // Coordinates are small public integers. Keep the signed difference
            // small instead of multiplying by a full-width field representative.
            if x >= self.xs[i] {
                y = (y * (x - self.xs[i]) + &self.coefficients[i]) % &field.modulus;
            } else {
                let product = y * (self.xs[i] - x) % &field.modulus;
                y = (&self.coefficients[i] + &field.modulus - product) % &field.modulus;
            }
        }
        y
    }
}
pub struct Sharing {
    pub layout: Layout,
    secret: Field,
    blind: Field,
}
pub struct Generated {
    pub roots: Vec<Block>,
    /// Indexed by physical recipient, then batch slot.
    pub packages: Vec<Vec<Bundle>>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Value(BigUint),
    Rejected,
}
/// Authentication cache, constructed only by `authenticate`. Fields are private
/// so the runtime cannot accidentally promote an unchecked packet to a receipt.
pub(crate) struct VerifiedBundle {
    context: Block,
    slot: usize,
    root: Block,
    owner: usize,
    total: usize,
    range: Range<usize>,
    bundle: Bundle,
}
impl VerifiedBundle {
    pub(crate) fn bundle(&self) -> &Bundle {
        &self.bundle
    }
    pub(crate) fn tickets(&self) -> usize {
        self.range.len()
    }
}
fn commitment(context: &Block, s: &Share) -> Block {
    crypto::hash(b"hashrand-vs/share/v1", &[context, &s.value, &s.blind])
}
pub fn slot_context(context: Block, slot: usize) -> Block {
    crypto::hash(
        b"hashrand-vs/slot/v1",
        &[&context, &(slot as u64).to_le_bytes()],
    )
}
impl Sharing {
    pub fn new(layout: Layout) -> Self {
        Self {
            secret: Field::new(255, 19, layout.total),
            blind: Field::new(521, 1, layout.total),
            layout,
        }
    }
    pub fn generate(
        &self,
        context: Block,
        bits: &[u32],
        invalid_polynomial: bool,
    ) -> Result<Generated> {
        ensure!(
            !bits.is_empty() && bits.iter().all(|&b| b > 0 && b <= 254),
            "contribution bit widths"
        );
        let mut roots = Vec::with_capacity(bits.len());
        let mut packages: Vec<_> = self
            .layout
            .ranges
            .iter()
            .map(|_| Vec::with_capacity(bits.len()))
            .collect();
        for (slot, &width) in bits.iter().enumerate() {
            let ctx = slot_context(context, slot);
            let mut raw = [0u8; 32];
            getrandom::fill(&mut raw).map_err(|e| anyhow::anyhow!("randomness: {e}"))?;
            let secret =
                BigUint::from_bytes_be(&raw) & ((BigUint::one() << width) - BigUint::one());
            let p = self.secret.polynomial(secret, self.layout.threshold)?;
            let r = self
                .blind
                .polynomial(self.blind.random()?, self.layout.threshold)?;
            let mut shares: Vec<_> = (1..=self.layout.total)
                .map(|x| Share {
                    value: self.secret.encode(&self.secret.evaluate(&p, x)),
                    blind: self.blind.encode(&self.blind.evaluate(&r, x)),
                })
                .collect();
            if invalid_polynomial {
                let last = shares.last_mut().unwrap();
                let changed =
                    (self.secret.decode(&last.value).unwrap() + 1u8) % &self.secret.modulus;
                last.value = self.secret.encode(&changed);
            }
            let leaves: Vec<_> = shares.iter().map(|s| commitment(&ctx, s)).collect();
            let tree = IndexedTree::new(ctx, &leaves);
            roots.push(tree.root());
            let mut shares = shares.into_iter();
            for (party, range) in self.layout.ranges.iter().enumerate() {
                packages[party].push(Bundle {
                    shares: shares.by_ref().take(range.len()).collect(),
                    proof: tree.range_proof(range.start, range.len()).unwrap(),
                });
            }
        }
        Ok(Generated { roots, packages })
    }
    pub fn verify(
        &self,
        context: Block,
        slot: usize,
        root: Block,
        owner: usize,
        bundle: &Bundle,
    ) -> bool {
        let Some(range) = self.layout.ranges.get(owner) else {
            return false;
        };
        if bundle.shares.len() != range.len()
            || bundle
                .shares
                .iter()
                .any(|s| !self.secret.canonical(&s.value) || !self.blind.canonical(&s.blind))
        {
            return false;
        }
        let ctx = slot_context(context, slot);
        let leaves: Vec<_> = bundle.shares.iter().map(|s| commitment(&ctx, s)).collect();
        verify_range(
            ctx,
            root,
            self.layout.total,
            range.start,
            &leaves,
            &bundle.proof,
        )
        .is_some()
    }
    pub(crate) fn authenticate(
        &self,
        context: Block,
        slot: usize,
        root: Block,
        owner: usize,
        bundle: Bundle,
    ) -> Option<VerifiedBundle> {
        self.verify(context, slot, root, owner, &bundle)
            .then(|| VerifiedBundle {
                context,
                slot,
                root,
                owner,
                total: self.layout.total,
                range: self.layout.ranges[owner].clone(),
                bundle,
            })
    }
    pub(crate) fn recover_verified<'a>(
        &self,
        context: Block,
        slot: usize,
        root: Block,
        bundles: impl IntoIterator<Item = &'a VerifiedBundle>,
        bits: u32,
    ) -> Option<Outcome> {
        let mut owners = std::collections::BTreeSet::new();
        self.recover_from(
            context,
            slot,
            root,
            bundles.into_iter().filter_map(|v| {
                (v.context == context
                    && v.slot == slot
                    && v.root == root
                    && v.total == self.layout.total
                    && self.layout.ranges.get(v.owner) == Some(&v.range)
                    && owners.insert(v.owner))
                .then_some((v.owner, &v.bundle))
            }),
            bits,
        )
    }
    /// Canonical valid bundles, never the number of physical senders, determine rank.
    pub fn recover(
        &self,
        context: Block,
        slot: usize,
        root: Block,
        bundles: &BTreeMap<usize, Bundle>,
        bits: u32,
    ) -> Option<Outcome> {
        self.recover_from(
            context,
            slot,
            root,
            bundles.iter().filter_map(|(&owner, bundle)| {
                self.verify(context, slot, root, owner, bundle)
                    .then_some((owner, bundle))
            }),
            bits,
        )
    }
    fn recover_from<'a>(
        &self,
        context: Block,
        slot: usize,
        root: Block,
        bundles: impl IntoIterator<Item = (usize, &'a Bundle)>,
        bits: u32,
    ) -> Option<Outcome> {
        let mut secret = Vec::new();
        let mut blind = Vec::new();
        for (owner, bundle) in bundles {
            for (offset, s) in bundle.shares.iter().enumerate() {
                if secret.len() == self.layout.threshold {
                    break;
                }
                let x = self.layout.ranges[owner].start + offset + 1;
                secret.push((x, self.secret.decode(&s.value).unwrap()));
                blind.push((x, self.blind.decode(&s.blind).unwrap()));
            }
            if secret.len() == self.layout.threshold {
                break;
            }
        }
        if secret.len() < self.layout.threshold {
            return None;
        }
        secret.sort_unstable_by_key(|point| point.0);
        blind.sort_unstable_by_key(|point| point.0);
        let p = self.secret.interpolate(&secret);
        let r = self.blind.interpolate(&blind);
        let ctx = slot_context(context, slot);
        let leaves: Vec<_> = (1..=self.layout.total)
            .map(|x| {
                commitment(
                    &ctx,
                    &Share {
                        value: self.secret.encode(&p.at(&self.secret, x)),
                        blind: self.blind.encode(&r.at(&self.blind, x)),
                    },
                )
            })
            .collect();
        let value = p.at(&self.secret, 0);
        if IndexedTree::new(ctx, &leaves).root() == root && value < (BigUint::one() << bits) {
            Some(Outcome::Value(value))
        } else {
            Some(Outcome::Rejected)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_coordinate_evaluation_matches_field_arithmetic() {
        for (bits, subtract) in [(255, 19), (521, 1)] {
            let f = Field::new(bits, subtract, 100);
            let coefficients: Vec<_> = (0..7)
                .map(|i| &f.modulus - BigUint::from(i + 1u8))
                .collect();
            let points = [2, 7, 13, 29, 40, 65, 90].map(|x| (x, f.evaluate(&coefficients, x)));
            let p = f.interpolate(&points);
            for x in 0..=100 {
                assert_eq!(p.at(&f, x), f.evaluate(&coefficients, x));
            }
            let encoded = f.encode(&(&f.modulus - 1u8));
            assert!(f.canonical(&encoded));
            assert!(!f.canonical(&f.encode(&f.modulus)));
            assert!(!f.canonical(&encoded[1..]));
        }
    }

    #[test]
    fn buffered_coefficients_have_the_requested_degree_and_canonical_values() {
        for (bits, subtract) in [(8, 5), (255, 19), (521, 1)] {
            let field = Field::new(bits, subtract, 100);
            for threshold in [1, 33, 67, 257] {
                let polynomial = field.polynomial(7u8.into(), threshold).unwrap();
                assert_eq!(polynomial.len(), threshold);
                assert_eq!(polynomial[0], BigUint::from(7u8));
                assert!(polynomial.iter().all(|v| v < &field.modulus));
            }
        }
    }

    #[test]
    fn cached_authentication_binds_every_public_coordinate_and_deduplicates_owners() {
        let s = Sharing::new(Layout::new(&[3u8; 4].map(BigUint::from), &4u8.into(), 100).unwrap());
        let context = [5; 32];
        let g = s.generate(context, &[64, 64], false).unwrap();
        let verified: Vec<_> = (0..4)
            .map(|owner| {
                s.authenticate(context, 0, g.roots[0], owner, g.packages[owner][0].clone())
                    .unwrap()
            })
            .collect();
        let expected = s.recover_verified(context, 0, g.roots[0], &verified, 64);
        assert!(matches!(expected, Some(Outcome::Value(_))));
        assert_eq!(
            s.recover_verified(context, 0, g.roots[0], verified.iter().rev(), 64),
            expected
        );
        assert_eq!(
            s.recover_verified(context, 0, g.roots[0], [&verified[0], &verified[0]], 64),
            None
        );
        assert_eq!(
            s.recover_verified([6; 32], 0, g.roots[0], &verified, 64),
            None
        );
        assert_eq!(
            s.recover_verified(context, 1, g.roots[0], &verified, 64),
            None
        );
        assert_eq!(
            s.recover_verified(context, 0, g.roots[1], &verified, 64),
            None
        );
        let other = Sharing::new(
            Layout::new(&[2u8, 4, 4, 2].map(BigUint::from), &4u8.into(), 100).unwrap(),
        );
        assert_eq!(
            other.recover_verified(context, 0, g.roots[0], &verified, 64),
            None
        );
    }

    #[test]
    fn cached_recovery_still_rebuilds_the_entire_polynomial_commitment() {
        let s = Sharing::new(Layout::new(&[3u8; 4].map(BigUint::from), &4u8.into(), 100).unwrap());
        let ctx = [5; 32];
        let g = s.generate(ctx, &[64], true).unwrap();
        let verified: Vec<_> = (0..2)
            .map(|i| {
                s.authenticate(ctx, 0, g.roots[0], i, g.packages[i][0].clone())
                    .unwrap()
            })
            .collect();
        // The corrupted final ticket belongs to neither supplied owner.
        assert_eq!(
            s.recover_verified(ctx, 0, g.roots[0], &verified, 64),
            Some(Outcome::Rejected)
        );
        assert_eq!(
            bincode::serialize(&(0usize, &g.packages[0][0])).unwrap(),
            bincode::serialize(&crate::msg::SharePacket {
                slot: 0,
                bundle: g.packages[0][0].clone()
            })
            .unwrap()
        );
    }
}
