//! Public deterministic recovery tables. Never expand integer weights into shares.
use crate::Parameters;
use anyhow::{Result, ensure};
use num_bigint::BigUint;
use num_traits::Zero;
use types::Policy;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupKind {
    Cyclic,
    ThreeComplement,
}
#[derive(Clone, Debug)]
pub struct GroupPlan {
    pub kind: GroupKind,
    /// Sorted physical recoverer IDs K_d for every dealer d.
    pub groups: Vec<Vec<usize>>,
    pub edges: usize,
    pub max_load: usize,
    pub self_edges: usize,
    pub baseline_edges: usize,
    pub baseline_max_load: usize,
}
impl GroupPlan {
    /// Version 1's proven optimization domain; all other inputs retain sampling.
    pub fn select(policy: &Policy, bits: u32, force_three: bool) -> Result<Option<Self>> {
        policy.validate_async()?;
        let n = policy.n();
        if n > 60 || bits != 40 || policy.weights().iter().any(|w| w >= policy.threshold()) {
            return Ok(None);
        }
        let original = Parameters::new(policy, bits)?;
        // Equal weights use the exact-quota cyclic branch even in the
        // complement ablation; the complement budget proof uses the general
        // weighted quotas and must not override the smaller equal-weight quota.
        let equal = policy.weights().iter().all(|w| w == &policy.weights()[0]);
        if !force_three || equal {
            let groups = (0..n)
                .map(|d| {
                    let mut group = vec![];
                    let mut total = BigUint::zero();
                    for offset in 0..n {
                        let id = (d + offset) % n;
                        group.push(id);
                        total += &policy.weights()[id];
                        if &total >= policy.threshold() {
                            break;
                        }
                    }
                    group.sort_unstable();
                    group
                })
                .collect();
            let candidate = Self::checked(policy, &original, GroupKind::Cyclic, groups)?;
            if candidate.within_bounds() {
                return Ok(Some(candidate));
            }
        }
        let mut ids: Vec<_> = (0..n).collect();
        ids.sort_by(|&a, &b| {
            policy.weights()[b]
                .cmp(&policy.weights()[a])
                .then(a.cmp(&b))
        });
        let mut total = BigUint::zero();
        let mut blocks = vec![];
        for id in ids {
            total += &policy.weights()[id];
            blocks.push((policy.weights()[id].clone(), vec![id]));
            if total >= policy.threshold() * 2u8 {
                break;
            }
        }
        ensure!(
            blocks.len() >= 3,
            "strict weight cap requires three prefix members"
        );
        while blocks.len() > 3 {
            blocks.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
            let a = blocks.remove(0);
            let b = blocks.remove(0);
            let mut members = a.1;
            members.extend(b.1);
            members.sort_unstable();
            blocks.push((a.0 + b.0, members));
        }
        // This size ordering is essential for the max-load bound when n mod 3 != 0.
        blocks.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(a.1.cmp(&b.1)));
        let groups = (0..n)
            .map(|d| {
                let mut group: Vec<_> = blocks
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| *i != d % 3)
                    .flat_map(|(_, b)| b.1.iter().copied())
                    .collect();
                group.sort_unstable();
                group
            })
            .collect();
        let candidate = Self::checked(policy, &original, GroupKind::ThreeComplement, groups)?;
        ensure!(
            candidate.within_bounds(),
            "three-complement uniform budget invariant"
        );
        Ok(Some(candidate))
    }
    fn checked(
        policy: &Policy,
        original: &Parameters,
        kind: GroupKind,
        groups: Vec<Vec<usize>>,
    ) -> Result<Self> {
        ensure!(groups.len() == policy.n(), "one recovery group per dealer");
        let mut loads = vec![0; policy.n()];
        let mut self_edges = 0;
        for (d, group) in groups.iter().enumerate() {
            ensure!(
                group.windows(2).all(|w| w[0] < w[1]) && group.iter().all(|&i| i < policy.n()),
                "canonical recovery group"
            );
            ensure!(
                policy.authorized(group.iter().copied())?,
                "recovery group below threshold"
            );
            for &i in group {
                loads[i] += 1;
            }
            self_edges += usize::from(group.binary_search(&d).is_ok());
        }
        Ok(Self {
            kind,
            edges: loads.iter().sum(),
            max_load: *loads.iter().max().unwrap(),
            self_edges,
            groups,
            baseline_edges: original.edge_bound(),
            baseline_max_load: *original.quotas.iter().max().unwrap(),
        })
    }
    pub fn within_bounds(&self) -> bool {
        3 * self.edges <= 2 * self.baseline_edges && 6 * self.max_load <= 5 * self.baseline_max_load
    }
    pub fn lists(&self) -> Vec<Vec<usize>> {
        let mut lists = vec![vec![]; self.groups.len()];
        for (d, group) in self.groups.iter().enumerate() {
            for &i in group {
                lists[i].push(d);
            }
        }
        lists
    }
    pub fn digest(&self) -> [u8; 32] {
        let mut bytes = vec![match self.kind {
            GroupKind::Cyclic => 0,
            GroupKind::ThreeComplement => 1,
        }];
        bytes.extend_from_slice(&(self.groups.len() as u32).to_le_bytes());
        for group in &self.groups {
            bytes.extend_from_slice(&(group.len() as u32).to_le_bytes());
            for &i in group {
                bytes.extend_from_slice(&(i as u32).to_le_bytes());
            }
        }
        crypto::hash(b"whcc/public-recovery-table/v1", &[&bytes])
    }
}
