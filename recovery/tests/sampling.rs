use num_bigint::BigUint;
use num_traits::One;
use recovery::{Assignments, Parameters};
use types::Policy;
fn equal(n: usize, t: usize) -> Policy {
    Policy::new(vec![BigUint::one(); n], t.into()).unwrap()
}
#[test]
fn paper_equal_weight_quotas_and_exact_coverage_bound() {
    let p = Parameters::new(&equal(150, 50), 40).unwrap();
    assert_eq!(p.quotas, vec![42; 150]);
    let q = Parameters::new(&equal(150, 50), 64).unwrap();
    assert_eq!(q.quotas, vec![58; 150]);
    for params in [p, q] {
        let d = params.quotas[0];
        let rhs = BigUint::from(150u16).pow(101);
        let bound = |d| {
            (BigUint::from(150u16) * BigUint::from(150 - d).pow(101))
                << params.statistical_bits as usize
        };
        assert!(bound(d) <= rhs);
        assert!(bound(d - 1) > rhs);
        assert_eq!(params.edge_bound(), 150 * d);
    }
}
#[test]
fn huge_skewed_weights_have_exact_quotas_and_global_edge_budget() {
    let huge = BigUint::one() << 1024usize;
    let policy = Policy::new(
        vec![huge.clone(), 1u8.into(), 2u8.into(), 3u8.into()],
        2u8.into(),
    )
    .unwrap();
    let p = Parameters::new(&policy, 40).unwrap();
    assert_eq!(p.quotas, vec![4, 1, 1, 1]);
    assert!(p.edge_bound() <= 4 * (p.a + 1));
}
#[test]
fn unbiased_bounded_draw_rejects_modulo_bias_and_samples_without_replacement() {
    let p = Parameters {
        a: 1,
        quotas: vec![1; 3],
        statistical_bits: 1,
    };
    let mut calls = 0;
    let list = p
        .sample_with(0, |b| {
            calls += 1;
            b.copy_from_slice(&(if calls == 1 { 0u64 } else { 5 }).to_le_bytes());
            Ok(())
        })
        .unwrap();
    // For bound=3, raw zero lies in the rejection interval, 5 selects index 2.
    assert_eq!(calls, 2);
    assert_eq!(list, vec![2]);
    let p = Parameters::new(&equal(20, 6), 4).unwrap();
    for id in 0..20 {
        let list = p.sample(id).unwrap();
        assert_eq!(list.len(), p.quotas[id]);
        assert!(list.windows(2).all(|x| x[0] < x[1]));
        assert!(list.iter().all(|&d| d < 20));
    }
}
#[test]
fn rbc_lists_are_canonical_immutable_context_bound_and_grow_late() {
    let p = Parameters {
        a: 1,
        quotas: vec![2; 4],
        statistical_bits: 1,
    };
    let context = [3; 32];
    let mut a = Assignments::new(p.clone(), context);
    let valid = p.encode(context, 0, &[1, 3]).unwrap();
    assert!(a.deliver(0, &valid));
    assert!(a.authorized(0, 3));
    assert!(!a.deliver(0, &p.encode(context, 0, &[0, 2]).unwrap()));
    assert!(!a.authorized(0, 0));
    let mut invalid = p.encode(context, 1, &[0, 1]).unwrap();
    invalid[36..40].copy_from_slice(&0u32.to_le_bytes());
    assert!(!a.deliver(1, &invalid));
    assert!(!a.deliver(1, &p.encode(context, 1, &[0, 1]).unwrap()));
    assert!(!a.deliver(2, &p.encode([4; 32], 2, &[0, 1]).unwrap()));
    assert!(!a.authorized(2, 0));
    assert!(a.deliver(3, &p.encode(context, 3, &[0, 3]).unwrap()));
    assert!(a.authorized(3, 3));
}
