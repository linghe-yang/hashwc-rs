use crypto::{hash, wire_commitment};
use num_bigint::BigUint;
use types::{Error, Policy};
use wcss::{Backend, Circuit, Limits, Op, Setup, compact};

fn policy(w: &[u64], t: u64) -> Policy {
    Policy::new(w.iter().copied().map(BigUint::from).collect(), t.into()).unwrap()
}

#[test]
fn fixed_compiler_matches_all_small_weighted_thresholds() {
    let mut cases = 0;
    for n in 1..=4u32 {
        for mut code in 0..3usize.pow(n) {
            let w: Vec<u64> = (0..n)
                .map(|_| {
                    let x = 2 * (code % 3 + 1) as u64;
                    code /= 3;
                    x
                })
                .collect();
            // Odd thresholds explicitly check ceil(T/gcd), not floor division.
            for t in 1..=w.iter().sum() {
                let p = policy(&w, t);
                let c = Circuit::build_clean(p.clone(), Limits::default()).unwrap();
                assert_eq!(c.policy().encode(), p.encode());
                for mask in 0..1usize << n {
                    let ids: Vec<_> = (0..n as usize).filter(|i| mask & (1 << i) != 0).collect();
                    assert_eq!(
                        c.evaluate(&ids).unwrap(),
                        p.authorized(ids).unwrap(),
                        "w={w:?}, t={t}, mask={mask}"
                    );
                    cases += 1;
                }
            }
        }
    }
    println!("clean circuit coalition checks: {cases}");
}

#[test]
fn fixed_compiler_handles_multiword_weights_and_enforces_limits_without_fallback() {
    let scale = BigUint::from(1u8) << 1024;
    let weights: Vec<_> = [1u8, 3, 5, 7]
        .into_iter()
        .map(|x| &scale + BigUint::from(x))
        .collect();
    for t in [
        &scale + BigUint::from(1u8),
        (&scale << 1) + BigUint::from(5u8),
    ] {
        let p = Policy::new(weights.clone(), t).unwrap();
        let c = Circuit::build_clean(p.clone(), Limits::default()).unwrap();
        for mask in 0..16 {
            let ids: Vec<_> = (0..4).filter(|i| mask & (1 << i) != 0).collect();
            assert_eq!(c.evaluate(&ids).unwrap(), p.authorized(ids).unwrap());
        }
        assert!(
            Setup::new_clean(
                p,
                Limits {
                    bit_layers: 64,
                    ..Limits::default()
                }
            )
            .is_err()
        );
    }
    assert!(matches!(
        Setup::new_clean(
            policy(&[1; 4], 2),
            Limits {
                gates: 0,
                ..Limits::default()
            }
        ),
        Err(Error::ResourceLimit("gates"))
    ));
    assert!(
        Setup::new_clean(
            policy(&[1; 4], 2),
            Limits {
                parties: 3,
                ..Limits::default()
            }
        )
        .is_err()
    );
}

#[test]
fn generated_css_both_layouts_match_all_coalitions_and_exact_field_counts() {
    let mut coalitions = 0;
    for w in [
        vec![7],
        vec![1, 1],
        vec![2, 3, 5],
        vec![2, 4, 6, 8],
        vec![1, 3, 4, 7, 9],
    ] {
        let total: u64 = w.iter().sum();
        for t in [1, (total / 3).max(1), (total - 1).max(1), total] {
            let s = Setup::new_clean(policy(&w, t), Limits::default()).unwrap();
            let n = w.len();
            let or_count = s
                .circuit()
                .gates()
                .iter()
                .filter(|g| g.op == Op::Or)
                .count();
            assert_eq!(s.backend(), Backend::GeneratedAnd0Or1);
            assert_eq!(s.correction_blocks(), or_count);
            let context = hash(b"clean/test/context", &[&s.id()]);
            let (full, shares) = wcss::share(&s, &context, &[255; 32], &[21; 32]);
            let (small, compact_shares) = compact::share(&s, &context, &[255; 32], &[21; 32]);
            assert_eq!(*shares, *compact_shares);
            assert!(full.gates.is_empty());
            assert_eq!(full.corrections.len(), or_count);
            assert_eq!(
                full.byte_len(),
                96 + 32 * (n + s.circuit().nodes() + or_count)
            );
            assert_eq!(small.byte_len(), 96 + 32 * (n + or_count));
            assert_eq!(wcss::Public::decode(&s, &full.encode()).unwrap(), full);
            let bytes = small.encode();
            assert_eq!(compact::Public::decode(&s, &bytes).unwrap(), small);
            let view = compact::PublicView::decode(&s, &bytes).unwrap();
            assert_eq!(wcss::share(&s, &context, &[255; 32], &[21; 32]).0, full);
            for mask in 0..1usize << n {
                let selected: Vec<_> = (0..n)
                    .filter(|i| mask & (1 << i) != 0)
                    .map(|i| (i, shares[i]))
                    .collect();
                let expected = if s
                    .circuit()
                    .policy()
                    .authorized(selected.iter().map(|x| x.0))
                    .unwrap()
                {
                    Ok([255; 32])
                } else {
                    Err(Error::InsufficientShares)
                };
                assert_eq!(wcss::reconstruct(&s, &context, &full, &selected), expected);
                assert_eq!(
                    compact::reconstruct(&s, &context, &small, &selected),
                    expected
                );
                assert_eq!(
                    view.reconstruct(&s, &context, selected.iter().copied())
                        .map(|r| *r.key),
                    expected
                );
                coalitions += 1;
            }
        }
    }
    println!("generated CSS coalition checks (each in three recovery paths): {coalitions}");
}

#[test]
fn generated_gate_kernel_uses_no_and_or_left_corrections_and_rejects_bad_witnesses() {
    let s = Setup::new_clean(policy(&[3; 4], 4), Limits::default()).unwrap();
    let ctx = [45; 32];
    let (p, shares) = wcss::share(&s, &ctx, &[22; 32], &[19; 32]);
    let mut tokens = vec![[0; 32]; s.circuit().nodes()];
    tokens[1] = p.true_token;
    tokens[2..s.circuit().base()].copy_from_slice(&shares);
    let mut seen = [false; 2];
    for (i, g) in s.circuit().gates().iter().enumerate() {
        let wire = s.circuit().base() + i;
        let out = match g.op {
            Op::And => {
                seen[0] = true;
                assert!(s.correction_index(i, 0).is_none());
                assert!(s.correction_index(i, 1).is_none());
                wcss::evaluate_gate(&s, &ctx, i, 3, &[tokens[g.left], tokens[g.right]], |_| {
                    panic!("AND must have no correction")
                })
                .unwrap()
            }
            Op::Or => {
                seen[1] = true;
                assert!(s.correction_index(i, 0).is_none());
                let left = wcss::evaluate_gate(&s, &ctx, i, 1, &[tokens[g.left], [0; 32]], |_| {
                    panic!("OR-left must have no correction")
                })
                .unwrap();
                let mut reads = 0;
                let right = wcss::evaluate_gate(&s, &ctx, i, 2, &[[0; 32], tokens[g.right]], |j| {
                    reads += 1;
                    p.correction(j)
                })
                .unwrap();
                assert_eq!(reads, 1);
                assert_eq!(left, right);
                assert!(
                    wcss::evaluate_gate(
                        &s,
                        &ctx,
                        i,
                        3,
                        &[tokens[g.left], tokens[g.right]],
                        |_| panic!()
                    )
                    .is_none()
                );
                left
            }
        };
        assert_eq!(wire_commitment(&ctx, wire, &out), p.wires[wire]);
        assert!(wcss::evaluate_gate(&s, &ctx, i, 0, &[[0; 32]; 2], |_| panic!()).is_none());
        tokens[wire] = out;
    }
    assert_eq!(seen, [true, true]);
    assert!(wcss::evaluate_gate(&s, &ctx, usize::MAX, 3, &[[0; 32]; 2], |_| panic!()).is_none());
}

#[test]
fn generated_shape_and_context_reject_wrong_format_duplicates_and_malformed_bytes() {
    let p = policy(&[3; 4], 4);
    let s = Setup::new_clean(p.clone(), Limits::default()).unwrap();
    let old = Setup::new(p.clone(), Limits::default()).unwrap();
    let optimized = Setup::new_optimized(p, Limits::default()).unwrap();
    assert_ne!(s.id(), old.id());
    assert_ne!(s.id(), optimized.id());
    let (full, shares) = wcss::share(&s, &[1; 32], &[2; 32], &[3; 32]);
    let mut bad = full.clone();
    bad.gates.push([[0; 32]; 2]);
    assert!(!bad.valid_shape(&s));
    let mut bad = full.clone();
    bad.corrections.pop();
    assert!(!bad.valid_shape(&s));
    assert_eq!(
        wcss::reconstruct(&s, &[1; 32], &full, &vec![(0, shares[0]); 8]),
        Err(Error::InsufficientShares)
    );
    let selected: Vec<_> = shares.iter().copied().enumerate().collect();
    assert!(wcss::reconstruct(&s, &[4; 32], &full, &selected).is_err());
    let bytes = full.encode();
    for end in [0, 1, 31, 32, bytes.len() - 1] {
        assert!(wcss::Public::decode(&s, &bytes[..end]).is_err());
    }
    let mut extra = bytes;
    extra.push(0);
    assert!(wcss::Public::decode(&s, &extra).is_err());
}
