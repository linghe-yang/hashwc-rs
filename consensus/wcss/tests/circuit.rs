use num_bigint::BigUint;
use types::{Error, Policy};
use wcss::{Circuit, Limits, Setup};
fn policy(weights: &[u64], threshold: u64) -> Policy {
    Policy::new(
        weights.iter().map(|&w| w.into()).collect(),
        threshold.into(),
    )
    .unwrap()
}
#[test]
fn exhaustive_threshold_truth_tables() {
    // Every weight vector in {1,2,3}^n, every threshold, every subset (n <= 4).
    for n in 1u32..=4 {
        for code in 0..3usize.pow(n) {
            let mut code = code;
            let weights: Vec<u64> = (0..n)
                .map(|_| {
                    let w = (code % 3 + 1) as u64;
                    code /= 3;
                    w
                })
                .collect();
            for threshold in 1..=weights.iter().sum() {
                let p = policy(&weights, threshold);
                let c = Circuit::build(p.clone(), Limits::default()).unwrap();
                for mask in 0..1usize << n {
                    let ids: Vec<_> = (0..n as usize).filter(|i| mask & (1 << i) != 0).collect();
                    assert_eq!(
                        c.evaluate(&ids).unwrap(),
                        p.authorized(ids).unwrap(),
                        "weights={weights:?}, threshold={threshold}, mask={mask}"
                    );
                }
            }
        }
    }
}
#[test]
fn huge_coprime_weights_do_not_expand_parties() {
    let scale = BigUint::from(1u8) << 1024;
    let weights: Vec<_> = [1u8, 3, 5, 7]
        .iter()
        .map(|&x| &scale + BigUint::from(x))
        .collect();
    let p = Policy::new(weights, (&scale << 1) + BigUint::from(5u8)).unwrap();
    let c = Circuit::build(p.clone(), Limits::default()).unwrap();
    assert_eq!(c.base(), 6);
    assert!(c.gates().len() < 100_000);
    for mask in 0..16 {
        let ids: Vec<_> = (0..4).filter(|i| mask & (1 << i) != 0).collect();
        assert_eq!(c.evaluate(&ids).unwrap(), p.authorized(ids).unwrap());
    }
    assert_eq!(
        Setup::new(p.clone(), Limits::default()).unwrap().id(),
        Setup::new(p, Limits::default()).unwrap().id()
    );
}
#[test]
fn budgets_and_invalid_parameters_are_errors() {
    assert!(Policy::new(vec![], 1u8.into()).is_err());
    assert!(Policy::new(vec![0u8.into()], 1u8.into()).is_err());
    assert!(Policy::new(vec![1u8.into()], 0u8.into()).is_err());
    let p = policy(&[1, 1, 1, 1], 2);
    assert!(matches!(
        Circuit::build(
            p.clone(),
            Limits {
                gates: 0,
                ..Limits::default()
            }
        ),
        Err(Error::ResourceLimit(_))
    ));
    assert!(
        Circuit::build(
            p.clone(),
            Limits {
                parties: 3,
                ..Limits::default()
            }
        )
        .is_err()
    );
    assert!(
        Circuit::build(
            p,
            Limits {
                bit_layers: 1,
                ..Limits::default()
            }
        )
        .is_err()
    );
}
#[test]
fn full_width_key_and_unauthorized_cryptographic_closure() {
    let setup = Setup::new(policy(&[1, 2, 3, 4], 6), Limits::default()).unwrap();
    let (public, tokens) = wcss::share(&setup, &[1; 32], &[255; 32], &[2; 32]);
    assert_eq!(public.encode().len(), wcss::Public::encoded_len(&setup));
    assert_eq!(
        wcss::Public::decode(&setup, &public.encode()).unwrap(),
        public
    );
    for mask in 0..16 {
        let shares: Vec<_> = (0..4)
            .filter(|i| mask & (1 << i) != 0)
            .map(|i| (i, tokens[i]))
            .collect();
        let out = wcss::reconstruct(&setup, &[1; 32], &public, &shares);
        if setup
            .circuit()
            .policy()
            .authorized(shares.iter().map(|s| s.0))
            .unwrap()
        {
            assert_eq!(out.unwrap(), [255; 32]);
        } else {
            assert_eq!(out.unwrap_err(), Error::InsufficientShares);
        }
    }
}
