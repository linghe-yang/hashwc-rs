use hashrand::bwavss::{Layout, Outcome, Sharing};
use num_bigint::BigUint;
use std::collections::BTreeMap;
fn sharing() -> Sharing {
    Sharing::new(Layout::new(&[3u8, 2, 4, 3].map(BigUint::from), &BigUint::from(4u8), 100).unwrap())
}
#[test]
fn weighted_threshold_is_ticket_rank_not_physical_party_count() {
    let s = sharing();
    let ctx = [17; 32];
    let g = s.generate(ctx, &[64, 192], false).unwrap();
    let all: BTreeMap<_, _> = (0..4).map(|i| (i, g.packages[i][0].clone())).collect();
    let expected = s.recover(ctx, 0, g.roots[0], &all, 64).unwrap();
    assert!(matches!(expected, Outcome::Value(_)));
    for mask in 0..16 {
        let map: BTreeMap<_, _> = (0..4)
            .filter(|i| mask & (1 << i) != 0)
            .map(|i| (i, g.packages[i][0].clone()))
            .collect();
        let rank: usize = map.keys().map(|&i| s.layout.ranges[i].len()).sum();
        assert_eq!(
            s.recover(ctx, 0, g.roots[0], &map, 64),
            if rank >= 4 {
                Some(expected.clone())
            } else {
                None
            }
        );
    }
}
#[test]
fn authenticated_non_polynomial_sharing_is_rejected_by_every_authorized_subset() {
    let s = sharing();
    let ctx = [19; 32];
    let g = s.generate(ctx, &[64], true).unwrap();
    for i in 0..4 {
        assert!(s.verify(ctx, 0, g.roots[0], i, &g.packages[i][0]));
    }
    for mask in 0..16 {
        let map: BTreeMap<_, _> = (0..4)
            .filter(|i| mask & (1 << i) != 0)
            .map(|i| (i, g.packages[i][0].clone()))
            .collect();
        if map.keys().map(|&i| s.layout.ranges[i].len()).sum::<usize>() >= 4 {
            assert_eq!(
                s.recover(ctx, 0, g.roots[0], &map, 64),
                Some(Outcome::Rejected)
            );
        }
    }
}
#[test]
fn proofs_bind_owner_slot_context_and_every_virtual_share() {
    let s = sharing();
    let ctx = [19; 32];
    let g = s.generate(ctx, &[64, 64], false).unwrap();
    let bundle = &g.packages[0][0];
    assert!(s.verify(ctx, 0, g.roots[0], 0, bundle));
    assert!(!s.verify(ctx, 0, g.roots[0], 3, bundle));
    assert!(!s.verify([20; 32], 0, g.roots[0], 0, bundle));
    assert!(!s.verify(ctx, 1, g.roots[0], 0, bundle));
    let mut changed = bundle.clone();
    changed.shares[1].value[31] ^= 1;
    assert!(!s.verify(ctx, 0, g.roots[0], 0, &changed));
    let mut changed = bundle.clone();
    changed.shares.pop();
    assert!(!s.verify(ctx, 0, g.roots[0], 0, &changed));
    let mut changed = bundle.clone();
    changed.proof.push([0; 32]);
    assert!(!s.verify(ctx, 0, g.roots[0], 0, &changed));
}
#[test]
fn huge_original_weights_are_rejected_not_silently_reduced() {
    let w = BigUint::from(1u8) << 100usize;
    assert!(Layout::new(&vec![w.clone(); 4], &w, 4096).is_err());
}

#[test]
fn weighted_sampling_uses_ticket_mass_and_is_reproducible() {
    use hashrand::protocol::sample_committee;
    let layout = Layout::new(
        &[1u8, 1, 1, 97].map(BigUint::from),
        &BigUint::from(33u8),
        100,
    )
    .unwrap();
    let s = Sharing::new(layout);
    let mut saw_strict_subset = false;
    for i in 0..16 {
        let mut raw = [0u8; 32];
        raw[31] = i;
        let seed = types::Coin::from_be_bytes(128, raw).unwrap();
        let selected = sample_committee(&s, seed, [10; 32], 40);
        assert_eq!(selected, sample_committee(&s, seed, [10; 32], 40));
        assert!(selected.contains(&3));
        assert!(selected.windows(2).all(|w| w[0] < w[1]));
        saw_strict_subset |= selected.len() < 4;
    }
    assert!(saw_strict_subset);
}

#[test]
fn below_one_third_private_views_have_insufficient_rank_after_rounding_fix() {
    for w in [4usize, 5, 7, 8] {
        let t = (w + 2) / 3;
        let sharing = Sharing::new(
            Layout::new(&vec![BigUint::from(1u8); w], &BigUint::from(t), 100).unwrap(),
        );
        let g = sharing.generate([91; 32], &[66], false).unwrap();
        for mask in 0usize..1usize << w {
            let view: BTreeMap<_, _> = (0..w)
                .filter(|i| mask & (1usize << i) != 0)
                .map(|i| (i, g.packages[i][0].clone()))
                .collect();
            let b = view.len();
            let result = sharing.recover([91; 32], 0, g.roots[0], &view, 66);
            if 3 * b < w {
                assert_eq!(result, None, "W={w}, corrupt weight {b}");
            } else {
                assert!(matches!(result, Some(Outcome::Value(_))));
            }
        }
    }
}

#[test]
fn sui16_previous_boundary_coalition_can_no_longer_recover() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sui16-ceil.json");
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let weights: Vec<BigUint> = v["weights"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().parse().unwrap())
        .collect();
    let sharing = Sharing::new(Layout::new(&weights, &380u64.into(), 8192).unwrap());
    let g = sharing.generate([92; 32], &[66], false).unwrap();
    let mut view: BTreeMap<_, _> = [1usize, 4, 6]
        .into_iter()
        .map(|i| (i, g.packages[i][0].clone()))
        .collect();
    assert_eq!(
        view.keys()
            .map(|i| sharing.layout.ranges[*i].len())
            .sum::<usize>(),
        379
    );
    assert_eq!(sharing.recover([92; 32], 0, g.roots[0], &view, 66), None);
    view.insert(0, g.packages[0][0].clone());
    assert!(matches!(
        sharing.recover([92; 32], 0, g.roots[0], &view, 66),
        Some(Outcome::Value(_))
    ));
}
