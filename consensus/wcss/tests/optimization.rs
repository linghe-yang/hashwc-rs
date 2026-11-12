use num_bigint::BigUint;
use types::{Error, Policy};
use wcss::{CandidateStatus, Circuit, Construction, Limits, Setup};

fn policy(weights: &[u64], t: u64) -> Policy {
    Policy::new(
        weights.iter().copied().map(BigUint::from).collect(),
        t.into(),
    )
    .unwrap()
}
#[test]
fn deterministic_selection_preserves_original_policy_and_never_increases_size() {
    for weights in [
        vec![3; 8],
        vec![3; 16],
        vec![2, 3, 4, 2, 3, 4, 2, 4],
        vec![1, 1, 1, 40],
    ] {
        let p = policy(&weights, weights.iter().sum::<u64>() / 3);
        let old = Circuit::build(p.clone(), Limits::default()).unwrap();
        let a = Circuit::compile_optimized(p.clone(), Limits::default()).unwrap();
        let b = Circuit::compile_optimized(p.clone(), Limits::default()).unwrap();
        assert!(a.circuit.gates.len() <= old.gates.len());
        assert_eq!(a.circuit.policy.encode(), p.encode());
        assert_eq!(a.circuit.base(), old.base());
        assert_eq!(a.circuit.encode(), b.circuit.encode());
        assert_eq!(a.candidates, b.candidates);
        assert_eq!(a.selected, b.selected);
        assert_eq!(
            a.circuit.gates.len(),
            a.candidates
                .iter()
                .filter_map(|c| match c.status {
                    CandidateStatus::Built { gates } => Some(gates),
                    _ => None,
                })
                .min()
                .unwrap()
        );
        assert_ne!(
            Setup::new(p.clone(), Limits::default()).unwrap().id(),
            Setup::new_optimized(p, Limits::default()).unwrap().id()
        );
    }
    let tie = Circuit::compile_optimized(policy(&[1], 1), Limits::default()).unwrap();
    assert_eq!(tie.selected, Construction::Legacy);
}
#[test]
fn budgets_are_enforced_before_shortcuts_and_per_candidate() {
    let p = policy(&[3; 8], 8);
    let cap = Limits {
        gates: 60,
        ..Limits::default()
    };
    assert!(Circuit::build(p.clone(), cap).is_err());
    let c = Circuit::compile_optimized(p.clone(), cap).unwrap();
    assert_eq!(c.candidates[0].status, CandidateStatus::GateLimit);
    assert_eq!(c.selected, Construction::Cardinality);
    assert_eq!(c.circuit.gates.len(), 23);
    for limits in [
        Limits {
            gates: 0,
            ..Limits::default()
        },
        Limits {
            parties: 7,
            ..Limits::default()
        },
        Limits {
            bit_layers: 1,
            ..Limits::default()
        },
    ] {
        assert!(matches!(
            Circuit::build_optimized(p.clone(), limits),
            Err(Error::ResourceLimit(_))
        ));
    }
    let huge = BigUint::from(1u8) << 1024usize;
    let p = Policy::new(vec![huge.clone(); 4], huge).unwrap();
    assert_eq!(
        Circuit::build_optimized(
            p,
            Limits {
                bit_layers: 10,
                ..Limits::default()
            }
        )
        .unwrap_err(),
        Error::ResourceLimit("weight bit layers")
    );
}
#[test]
fn multiword_coprime_and_common_factor_policies_keep_exact_boundaries() {
    // Above machine integers and above the requested <= n log n bit regime.
    for bits in [65usize, 129, 359, 1024] {
        let scale = BigUint::from(1u8) << bits;
        for common in [false, true] {
            let weights: Vec<_> = [1u8, 3, 5, 7, 9, 11, 13, 15]
                .iter()
                .map(|&x| {
                    if common {
                        &scale * BigUint::from(x)
                    } else {
                        &scale + BigUint::from(x)
                    }
                })
                .collect();
            let exact: BigUint = weights[..3].iter().sum();
            for threshold in [
                &exact - BigUint::from(1u8),
                exact.clone(),
                &exact + BigUint::from(1u8),
            ] {
                let p = Policy::new(weights.clone(), threshold).unwrap();
                let c = Circuit::build_optimized(p.clone(), Limits::default()).unwrap();
                assert_eq!(c.base(), 10);
                assert_eq!(c.policy.encode(), p.encode());
                for mask in 0..256usize {
                    let ids: Vec<_> = (0..8).filter(|i| mask & (1 << i) != 0).collect();
                    assert_eq!(c.evaluate(&ids).unwrap(), p.authorized(ids).unwrap());
                }
            }
        }
    }
}
#[test]
fn optimized_css_preserves_authorized_and_unauthorized_closure() {
    // Exercise cardinality, ordered merge and normalization over all coalitions.
    for p in [
        policy(&[3; 8], 8),
        policy(&[2, 3, 4, 2, 3, 4, 2, 4], 8),
        policy(&[6, 9, 12, 6, 9, 12, 6, 12], 25),
    ] {
        let setup = Setup::new_optimized(p, Limits::default()).unwrap();
        let (public, tokens) = wcss::share(&setup, &[1; 32], &[255; 32], &[2; 32]);
        let (compact, compact_tokens) =
            wcss::compact::share(&setup, &[1; 32], &[255; 32], &[2; 32]);
        assert_eq!(
            wcss::Public::decode(&setup, &public.encode()).unwrap(),
            public
        );
        assert_eq!(
            wcss::compact::Public::decode(&setup, &compact.encode()).unwrap(),
            compact
        );
        for mask in 0..256usize {
            let ids: Vec<_> = (0..8).filter(|i| mask & (1 << i) != 0).collect();
            let shares: Vec<_> = ids.iter().map(|&i| (i, tokens[i])).collect();
            let compact_shares: Vec<_> = ids.iter().map(|&i| (i, compact_tokens[i])).collect();
            let expected = if setup.circuit.policy.authorized(ids).unwrap() {
                Ok([255; 32])
            } else {
                Err(Error::InsufficientShares)
            };
            assert_eq!(
                wcss::reconstruct(&setup, &[1; 32], &public, &shares),
                expected
            );
            assert_eq!(
                wcss::compact::reconstruct(&setup, &[1; 32], &compact, &compact_shares),
                expected
            );
        }
    }
}
