//! Exact alternatives to the legacy bit-layer sorter. No weight approximation.
use super::{Builder, Circuit, Limits, Op};
use num_bigint::BigUint;
use std::collections::BTreeMap;
use types::{Error, Policy, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Construction {
    Legacy,
    OrderedMerge,
    NormalizedLegacy,
    NormalizedOrderedMerge,
    Cardinality,
}
impl Construction {
    pub fn name(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::OrderedMerge => "ordered_merge",
            Self::NormalizedLegacy => "normalized_legacy",
            Self::NormalizedOrderedMerge => "normalized_ordered_merge",
            Self::Cardinality => "cardinality",
        }
    }
}
const CANDIDATES: [Construction; 5] = [
    Construction::Legacy,
    Construction::OrderedMerge,
    Construction::NormalizedLegacy,
    Construction::NormalizedOrderedMerge,
    Construction::Cardinality,
];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateStatus {
    Built { gates: usize },
    NotApplicable,
    GateLimit,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CandidateSize {
    pub construction: Construction,
    pub status: CandidateStatus,
}
#[derive(Clone, Debug)]
pub struct Compilation {
    pub circuit: Circuit,
    pub selected: Construction,
    pub candidates: Vec<CandidateSize>,
}

fn validate(policy: &Policy, limits: Limits) -> Result<()> {
    if policy.n() > limits.parties {
        return Err(Error::ResourceLimit("parties"));
    }
    if policy.total().bits() > limits.bit_layers {
        return Err(Error::ResourceLimit("weight bit layers"));
    }
    Ok(())
}
pub(super) fn compile(policy: Policy, limits: Limits) -> Result<Compilation> {
    validate(&policy, limits)?;
    let normalized = normalize(&policy)?;
    let mut best: Option<(Construction, Circuit)> = None;
    let mut candidates = Vec::with_capacity(CANDIDATES.len());
    for construction in CANDIDATES {
        let status = match candidate(&policy, normalized.as_ref(), limits, construction) {
            Ok(Some(circuit)) => {
                let gates = circuit.gates.len();
                // Strict comparison: legacy wins ties; all parties make the same choice.
                if best.as_ref().is_none_or(|(_, c)| gates < c.gates.len()) {
                    best = Some((construction, circuit));
                }
                CandidateStatus::Built { gates }
            }
            Ok(None) => CandidateStatus::NotApplicable,
            Err(Error::ResourceLimit("gates")) => CandidateStatus::GateLimit,
            Err(e) => return Err(e),
        };
        candidates.push(CandidateSize {
            construction,
            status,
        });
    }
    let (selected, circuit) = best.ok_or(Error::ResourceLimit("gates"))?;
    Ok(Compilation {
        circuit,
        selected,
        candidates,
    })
}
pub(super) fn compile_clean(policy: Policy, limits: Limits) -> Result<Circuit> {
    validate(&policy, limits)?;
    let normalized = normalize(&policy)?;
    // gcd = 1 is a no-op within the same algorithm, not a fallback compiler.
    let mut circuit = ordered_merge(normalized.as_ref().unwrap_or(&policy), limits)?;
    circuit.policy = policy;
    Ok(circuit)
}
fn gcd(mut a: BigUint, mut b: BigUint) -> BigUint {
    while b != BigUint::from(0u8) {
        let remainder = a % &b;
        a = b;
        b = remainder;
    }
    a
}
fn normalize(policy: &Policy) -> Result<Option<Policy>> {
    let mut divisor = policy.weights()[0].clone();
    for w in &policy.weights()[1..] {
        divisor = gcd(divisor, w.clone());
        if divisor == BigUint::from(1u8) {
            return Ok(None);
        }
    }
    if divisor == BigUint::from(1u8) {
        return Ok(None);
    }
    let threshold = (policy.threshold() + &divisor - BigUint::from(1u8)) / &divisor;
    Ok(Some(Policy::new(
        policy.weights().iter().map(|w| w / &divisor).collect(),
        threshold,
    )?))
}
fn builder(policy: &Policy, limits: Limits) -> Builder {
    Builder {
        circuit: Circuit {
            policy: policy.clone(),
            gates: vec![],
            output: 0,
            gate_columns: vec![],
        },
        intern: BTreeMap::new(),
        limit: limits.gates,
        column: 0,
    }
}
fn candidate(
    original: &Policy,
    normalized: Option<&Policy>,
    limits: Limits,
    construction: Construction,
) -> Result<Option<Circuit>> {
    let mut circuit = match construction {
        Construction::Legacy => Circuit::build(original.clone(), limits)?,
        Construction::OrderedMerge => ordered_merge(original, limits)?,
        Construction::NormalizedLegacy => {
            let Some(p) = normalized else { return Ok(None) };
            Circuit::build(p.clone(), limits)?
        }
        Construction::NormalizedOrderedMerge => {
            let Some(p) = normalized else { return Ok(None) };
            ordered_merge(p, limits)?
        }
        Construction::Cardinality => {
            let Some(k) = cardinality_threshold(original) else {
                return Ok(None);
            };
            let mut b = builder(original, limits);
            let mut refs: Vec<_> = (2..b.circuit.base()).collect();
            crate::sorting::odd_even_sort(&mut refs, |a, c| {
                Ok((b.gate(Op::And, a, c)?, b.gate(Op::Or, a, c)?))
            })?;
            b.circuit.output = refs[original.n() - k];
            b.prune()
        }
    };
    circuit.policy = original.clone();
    Ok(Some(circuit))
}

/// Exact k-of-n iff max weight of k-1 parties < T <= min weight of k parties.
fn cardinality_threshold(policy: &Policy) -> Option<usize> {
    let mut weights: Vec<_> = policy.weights().iter().collect();
    weights.sort();
    let mut smallest = BigUint::from(0u8);
    let mut largest_previous = BigUint::from(0u8);
    for k in 1..=policy.n() {
        smallest += weights[k - 1];
        if &largest_previous < policy.threshold() && policy.threshold() <= &smallest {
            return Some(k);
        }
        largest_previous += weights[policy.n() - k];
    }
    None
}
fn ordered_merge(policy: &Policy, limits: Limits) -> Result<Circuit> {
    let d = policy.total().bits();
    let offset = (BigUint::from(1u8) << d as usize) - policy.threshold();
    let mut b = builder(policy, limits);
    let mut carry: Vec<usize> = vec![];
    for bit in 0..d {
        b.column = bit;
        let mut refs: Vec<_> = policy
            .weights()
            .iter()
            .enumerate()
            .filter(|(_, w)| w.bit(bit))
            .map(|(i, _)| i + 2)
            .collect();
        if offset.bit(bit) {
            refs.push(1);
        }
        crate::sorting::odd_even_sort(&mut refs, |a, c| {
            Ok((b.gate(Op::And, a, c)?, b.gate(Op::Or, a, c)?))
        })?;
        carry.reverse();
        let refs = crate::sorting::odd_even_merge(&refs, &carry, 1, |a, c| {
            Ok((b.gate(Op::And, a, c)?, b.gate(Op::Or, a, c)?))
        })?;
        carry = refs.iter().rev().skip(1).step_by(2).copied().collect();
    }
    b.circuit.output = carry.first().copied().unwrap_or(0);
    Ok(b.prune())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_candidate_matches_every_small_threshold_and_subset() {
        for n in 1..=4u32 {
            for mut code in 0..3usize.pow(n) {
                let weights: Vec<BigUint> = (0..n)
                    .map(|_| {
                        let w = BigUint::from(code % 3 + 1);
                        code /= 3;
                        w
                    })
                    .collect();
                let total: BigUint = weights.iter().sum();
                let total = total.to_u64_digits()[0];
                for threshold in 1..=total {
                    let p = Policy::new(weights.clone(), threshold.into()).unwrap();
                    let normalized = normalize(&p).unwrap();
                    for kind in CANDIDATES {
                        let Some(c) =
                            candidate(&p, normalized.as_ref(), Limits::default(), kind).unwrap()
                        else {
                            continue;
                        };
                        assert_eq!(c.policy.encode(), p.encode());
                        for mask in 0..1usize << n {
                            let ids: Vec<_> =
                                (0..n as usize).filter(|i| mask & (1 << i) != 0).collect();
                            assert_eq!(
                                c.evaluate(&ids).unwrap(),
                                p.authorized(ids).unwrap(),
                                "kind={kind:?}, weights={weights:?}, T={threshold}, mask={mask}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn every_candidate_handles_dense_multiword_weights_at_threshold_boundaries() {
        let mut seed = 20261023u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for n in 2..=9 {
            for words in [1, 2, 3] {
                let weights: Vec<_> = (0..n)
                    .map(|_| {
                        let mut w = BigUint::from(1u8);
                        for _ in 0..words {
                            w = (w << 64usize) + BigUint::from(next());
                        }
                        w
                    })
                    .collect();
                let boundary: BigUint = weights[..n / 2].iter().sum();
                for t in [boundary.clone(), &boundary + BigUint::from(1u8)] {
                    let p = Policy::new(weights.clone(), t).unwrap();
                    let normalized = normalize(&p).unwrap();
                    for kind in CANDIDATES {
                        let Some(c) =
                            candidate(&p, normalized.as_ref(), Limits::default(), kind).unwrap()
                        else {
                            continue;
                        };
                        for mask in 0..1usize << n {
                            let ids: Vec<_> = (0..n).filter(|i| mask & (1 << i) != 0).collect();
                            assert_eq!(
                                c.evaluate(&ids).unwrap(),
                                p.authorized(ids).unwrap(),
                                "n={n}, words={words}, kind={kind:?}, mask={mask}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn cardinality_requires_a_gap_not_similar_looking_weights() {
        let make = |w: &[u64], t: u64| {
            Policy::new(w.iter().copied().map(BigUint::from).collect(), t.into()).unwrap()
        };
        assert_eq!(
            cardinality_threshold(&make(&[9, 10, 11, 9, 10, 11, 9, 12], 27)),
            Some(3)
        );
        assert_eq!(
            cardinality_threshold(&make(&[2, 3, 4, 2, 3, 4, 2, 4], 8)),
            None
        );
        assert_eq!(cardinality_threshold(&make(&[2, 3, 4], 2)), Some(1));
        assert_eq!(cardinality_threshold(&make(&[2, 3, 4], 9)), Some(3));
    }
}
