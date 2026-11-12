use num_bigint::BigUint;
use num_traits::{One, ToPrimitive};
use recovery::{
    Assignments, Parameters,
    ranked::{self, Codec},
};
use types::Policy;

#[test]
fn tight_quotas_cover_every_legal_corrupt_set_with_exact_integer_probabilities() {
    let mut coalitions = 0;
    for n in 3..=10 {
        for bits in [1, 4, 8, 40, 256] {
            for seed in 0..3 {
                let w: Vec<BigUint> = (0..n)
                    .map(|i| BigUint::from(1 + (17 * i + 11 * seed) % 29))
                    .collect();
                let total: BigUint = w.iter().sum();
                let policy = Policy::new(w.clone(), &total / 3u8).unwrap();
                let p = Parameters::new_tight(&policy, bits).unwrap();
                for (i, &d) in p.quotas.iter().enumerate() {
                    let old = ((BigUint::from(p.a * n) * &w[i] + &total - BigUint::one()) / &total)
                        .min(BigUint::from(n));
                    assert!(d >= 1 && BigUint::from(d) <= old);
                }
                assert!(p.edge_bound() <= n * n && p.edge_bound() <= n * (p.a + 1));
                for mask in 0..1usize << n {
                    let corrupt: BigUint =
                        (0..n).filter(|i| mask >> i & 1 != 0).map(|i| &w[i]).sum();
                    if &corrupt >= policy.threshold() {
                        continue;
                    }
                    let mut product = BigUint::from(n) << bits as usize;
                    let mut honest = 0;
                    for (i, &d) in p.quotas.iter().enumerate() {
                        if mask >> i & 1 == 0 {
                            product *= n - d;
                            honest += 1;
                        }
                    }
                    assert!(product <= BigUint::from(n).pow(honest));
                    coalitions += 1;
                }
            }
        }
    }
    assert_eq!(coalitions, 5885);
    println!("TIGHT_COVERAGE,{coalitions}");
}

#[test]
fn equal_and_wide_weights_use_the_same_formula_and_scale_invariant_quotas() {
    for n in [4, 16, 60, 150] {
        let policy = Policy::new(vec![3u8.into(); n], BigUint::from(n)).unwrap();
        let p = Parameters::new_tight(&policy, 40).unwrap();
        let m = p.a.max(1024).next_power_of_two();
        let base = BigUint::from(m * n);
        let expected = n
            - (BigUint::from(n) * (&base - BigUint::from(p.a)).pow(m as u32) / base.pow(m as u32))
                .to_usize()
                .unwrap();
        assert_eq!(p.quotas, vec![expected; n]);
    }
    let base = Policy::new(
        vec![1u8.into(), 2u8.into(), 3u8.into(), 6u8.into()],
        4u8.into(),
    )
    .unwrap();
    let scale = (BigUint::one() << 300usize) + BigUint::from(17u8);
    let wide = Policy::new(
        base.weights().iter().map(|w| w * &scale).collect(),
        base.threshold() * &scale,
    )
    .unwrap();
    assert_eq!(
        Parameters::new_tight(&base, 8).unwrap().quotas,
        Parameters::new_tight(&wide, 8).unwrap().quotas
    );
    let skew = Policy::new(
        vec![
            BigUint::one() << 1024usize,
            1u8.into(),
            2u8.into(),
            3u8.into(),
        ],
        2u8.into(),
    )
    .unwrap();
    assert_eq!(
        Parameters::new_tight(&skew, 40).unwrap().quotas,
        vec![4, 1, 1, 1]
    );
}

#[test]
fn colex_bijection_all_small_subsets_and_canonical_rejections() {
    for n in 1..=10 {
        for d in 0..=n {
            let c = Codec::new(n, d).unwrap();
            let mut ranks = std::collections::BTreeSet::new();
            for mask in 0..1usize << n {
                let list: Vec<_> = (0..n).filter(|i| mask >> i & 1 != 0).collect();
                if list.len() != d {
                    continue;
                }
                let bytes = c.encode([7; 32], &list).unwrap();
                assert_eq!(c.decode([7; 32], &bytes).unwrap(), list);
                ranks.insert(BigUint::from_bytes_le(&bytes[32..32 + c.rank_bytes()]));
                assert_eq!(ranked::join(ranked::split(&bytes).unwrap()), bytes);
                assert!(c.decode([8; 32], &bytes).is_err());
            }
            assert_eq!(BigUint::from(ranks.len()), ranked::binomial(n, d));
        }
    }
    for n in [16, 60, 256, 512, 1024, 4096] {
        for d in [0, 1, n / 3, n / 2, n - 1, n] {
            let c = Codec::new(n, d).unwrap();
            let list: Vec<_> = (n - d..n).collect();
            let bytes = c.encode([7; 32], &list).unwrap();
            assert_eq!(c.decode([7; 32], &bytes).unwrap(), list);
            assert!(c.decode([7; 32], &bytes[..bytes.len() - 1]).is_err());
            if 32 + c.rank_bytes() < bytes.len() {
                let mut bad = bytes.clone();
                *bad.last_mut().unwrap() = 1;
                assert!(c.decode([7; 32], &bad).is_err());
            }
            if c.rank_bytes() != 0 {
                let mut bad = bytes.clone();
                let value = ranked::binomial(n, d).to_bytes_le();
                bad[32..32 + c.rank_bytes()].fill(0);
                bad[32..32 + value.len()].copy_from_slice(&value);
                assert!(c.decode([7; 32], &bad).is_err());
            }
        }
    }
}

#[test]
fn invalid_complete_rank_is_final_and_never_authorizes_work() {
    let p = Parameters {
        a: 1,
        quotas: vec![2; 4],
        statistical_bits: 1,
    };
    let mut a = Assignments::new(p, [7; 32]);
    let codec = Codec::new(4, 2).unwrap();
    let good = codec.encode([7; 32], &[1, 3]).unwrap();
    let mut bad = good.clone();
    bad[63] = 1;
    assert!(!a.deliver_ranked(0, &bad));
    assert!(a.delivered(0));
    assert!(!a.deliver_ranked(0, &good));
    assert!(!a.authorized(0, 1));
    assert!(a.deliver_ranked(1, &good));
    assert!(a.authorized(1, 3));
    assert!(!a.deliver_ranked(1, &good));
}
