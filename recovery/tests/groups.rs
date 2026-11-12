use num_bigint::BigUint;
use recovery::{GroupKind, GroupPlan};
use types::Policy;
fn policy(w: &[u64], t: u64) -> Policy {
    Policy::new(w.iter().copied().map(BigUint::from).collect(), t.into()).unwrap()
}
#[test]
fn all_small_weight_matrix_inputs_have_covered_bounded_cyclic_groups() {
    for n in [8, 16, 24, 32, 40, 46, 60] {
        for low in [2u64, 3, 9] {
            let mut w: Vec<_> = (0..n)
                .map(|i| if low == 3 { 3 } else { low + (i % 3) as u64 })
                .collect();
            w[0] += (3 - w.iter().sum::<u64>() % 3) % 3;
            let p = policy(&w, w.iter().sum::<u64>() / 3);
            let plan = GroupPlan::select(&p, 40, false).unwrap().unwrap();
            assert_eq!(plan.kind, GroupKind::Cyclic);
            assert!(plan.within_bounds());
            assert_eq!(plan.self_edges, n);
            for (d, g) in plan.groups.iter().enumerate() {
                assert!(p.authorized(g.iter().copied()).unwrap());
                assert!(g.contains(&d));
            }
        }
    }
}
#[test]
fn complement_fallback_and_all_weight_bounded_corrupt_subsets_keep_a_recovery_witness() {
    let mut w = vec![23, 22, 21];
    w.extend([1; 13]);
    let p = policy(&w, 26);
    let plan = GroupPlan::select(&p, 40, false).unwrap().unwrap();
    assert_eq!(plan.kind, GroupKind::ThreeComplement);
    assert!(plan.within_bounds());
    for w in [[1, 1, 1, 1, 1, 1, 1], [1, 2, 3, 4, 5, 6, 7]] {
        let p = policy(&w, w.iter().sum::<u64>() / 3);
        for force in [false, true] {
            let plan = GroupPlan::select(&p, 40, force).unwrap().unwrap();
            for mask in 0u64..1 << w.len() {
                let bad: u64 = w
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| mask >> i & 1 == 1)
                    .map(|(_, x)| x)
                    .sum();
                if BigUint::from(bad) >= *p.threshold() {
                    continue;
                }
                for (d, g) in plan.groups.iter().enumerate() {
                    // Honest witness is a remote recoverer, or the honest dealer
                    // which must be able to use its own material without a fetch.
                    assert!(
                        g.iter()
                            .any(|&i| mask >> i & 1 == 0 && (i != d || mask >> d & 1 == 0))
                    );
                }
            }
        }
    }
}
#[test]
fn weights_are_exact_and_domain_fallback_is_explicit() {
    let small = policy(&[3; 16], 16);
    let scale = BigUint::from(1u8) << 240;
    let wide = Policy::new(
        small.weights().iter().map(|w| w * &scale).collect(),
        small.threshold() * &scale,
    )
    .unwrap();
    let a = GroupPlan::select(&small, 40, false).unwrap().unwrap();
    let b = GroupPlan::select(&wide, 40, false).unwrap().unwrap();
    assert_eq!(a.groups, b.groups);
    assert_eq!(a.digest(), b.digest());
    assert!(
        GroupPlan::select(&policy(&[2, 1, 1, 1, 1], 2), 40, false)
            .unwrap()
            .is_none()
    );
    assert!(GroupPlan::select(&small, 8, false).unwrap().is_none());
    assert!(
        GroupPlan::select(&policy(&[1; 61], 20), 40, false)
            .unwrap()
            .is_none()
    );
}

#[test]
fn equal_weight_complement_mode_keeps_the_exact_quota_cyclic_branch() {
    let p = policy(&[3; 60], 60);
    let g = GroupPlan::select(&p, 40, true).unwrap().unwrap();
    assert_eq!(g.kind, GroupKind::Cyclic);
    assert!(g.within_bounds());
}
#[test]
fn deterministic_skewed_weight_sweep_preserves_both_budgets() {
    let mut seed = 1701u64;
    for n in 4..=60 {
        for _ in 0..4 {
            let w: Vec<u64> = (0..n)
                .map(|_| {
                    seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                    1 + ((seed >> 32) % 1000)
                })
                .collect();
            let upper = w.iter().sum::<u64>() / 3;
            let lower = *w.iter().max().unwrap() + 1;
            if lower > upper {
                continue;
            }
            for t in [lower, upper] {
                let p = policy(&w, t);
                for force in [false, true] {
                    let g = GroupPlan::select(&p, 40, force).unwrap().unwrap();
                    assert!(g.within_bounds());
                    assert!(
                        g.groups
                            .iter()
                            .all(|k| p.authorized(k.iter().copied()).unwrap())
                    );
                }
            }
        }
    }
}

#[test]
fn finite_domain_checks_close_the_uniform_budget_lemmas() {
    // General weighted proof: prefix lemma and max-load inequality. The value
    // a depends only on n and kappa, so checking every n closes the finite part.
    for n in 4usize..=60 {
        let p = policy(&vec![3; n], n as u64);
        let original = recovery::Parameters::new(&p, 40).unwrap();
        let a = original.a;
        assert!(a >= 3 && 4 * a * n >= 3 * (n + 1) * (n + 1));
        assert!(6 * (2 * n).div_ceil(3) <= 5 * n.min(a));
        // Every strict-cap equal-weight input reduces to k = ceil(T/w).
        // With w=3, T=3(k-1)+1 realizes each permitted k at this n.
        for k in 2..=n.div_ceil(3) {
            let p = policy(&vec![3; n], (3 * (k - 1) + 1) as u64);
            let plan = GroupPlan::select(&p, 40, false).unwrap().unwrap();
            assert_eq!(plan.edges, n * k);
            assert_eq!(plan.max_load, k);
            assert!(plan.within_bounds());
        }
    }
}
