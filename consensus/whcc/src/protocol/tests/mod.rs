mod adversary;
mod completion;
mod runtime;
mod simulation;
use config::Node;
use sdc_types::Weight;
pub(super) fn nodes(weights: &[u64], threshold: u64, base: u16) -> Vec<Node> {
    (0..weights.len())
        .map(|id| {
            let mut node = Node::new();
            node.id = id;
            node.num_nodes = weights.len();
            node.session_id = [45; 32];
            node.weights = weights.iter().copied().map(Weight::from).collect();
            node.weight_threshold = Some(Weight::from(threshold));
            for peer in 0..weights.len() {
                node.net_map
                    .insert(peer, format!("127.0.0.1:{}", base + peer as u16));
                let (a, b) = (id.min(peer) as u64, id.max(peer) as u64);
                node.sk_map.insert(
                    peer,
                    crypto::hash(
                        b"test-only-pairwise-key",
                        &[&a.to_le_bytes(), &b.to_le_bytes()],
                    )
                    .to_vec(),
                );
            }
            node
        })
        .collect()
}
#[test]
fn aggregation_is_exact_at_ceiling_wrap_and_zero_coefficient_boundaries() {
    use crate::aggregate::aggregate as word_aggregate;
    let aggregate = |coefficients: &[sdc_types::Dyadic],
                     values: &[Option<num_bigint::BigUint>],
                     rounding_bits| {
        word_aggregate(coefficients, values, rounding_bits, 1)
            .map(|coin| coin.map(|c| c.bit(0).unwrap()))
    };
    use num_bigint::BigUint;
    use sdc_types::Dyadic;
    let a = |n: u64, e| Dyadic {
        numerator: Weight::from(n),
        exponent: e,
    };
    let value = |x: u64| Some(BigUint::from(x));
    // nu=2: Delta=8, D=16. ceil(7.5)=8, ceil(15.5) wraps to zero.
    assert_eq!(aggregate(&[a(1, 1)], &[value(15)], 2).unwrap(), Some(1));
    assert_eq!(
        aggregate(&[a(1, 0), a(1, 1)], &[value(15), value(1)], 2).unwrap(),
        Some(0)
    );
    assert_eq!(
        aggregate(&[a(0, 0), a(1, 0)], &[None, value(9)], 2).unwrap(),
        Some(1)
    );
    assert_eq!(aggregate(&[a(1, 4)], &[None], 2).unwrap(), None);
    assert!(aggregate(&[a(3, 1)], &[value(1)], 2).is_err());
    assert!(aggregate(&[a(1, 0)], &[value(16)], 2).is_err());
    // This increment is too small for f64, but changes the exact ceiling to 8.
    assert_eq!(
        aggregate(&[a(1, 0), a(1, 200)], &[value(7), value(1)], 2).unwrap(),
        Some(1)
    );
}

#[test]
fn multibit_aggregation_has_equal_buckets_exact_boundaries_and_wide_outputs() {
    use crate::aggregate::aggregate;
    use num_bigint::BigUint;
    use sdc_types::Dyadic;
    let a = |n, e| Dyadic {
        numerator: Weight::from(n),
        exponent: e,
    };
    let value = |n: u64| Some(BigUint::from(n));
    // nu=2, lambda=3: D=64, Delta=8; exhaustive uniform reference contribution.
    let mut buckets = [0; 8];
    for m in 0..64 {
        let word = aggregate(&[a(1u64, 0)], &[value(m)], 2, 3)
            .unwrap()
            .unwrap();
        buckets[word.to_be_bytes()[31] as usize] += 1;
    }
    assert_eq!(buckets, [8; 8]);
    let result = |v| {
        aggregate(&[a(1u64, 0), a(1, 200)], &[value(v), value(1)], 2, 3)
            .unwrap()
            .unwrap()
            .to_be_bytes()[31]
    };
    assert_eq!(result(7), 1);
    assert_eq!(result(55), 7);
    assert_eq!(result(63), 0);
    assert!(aggregate(&[a(1u64, 0)], &[value(64)], 2, 3).is_err());
    for (nu, bits) in [(64, 128), (64, 189), (1, 252)] {
        let expected = (BigUint::from(1u8) << bits as usize) - BigUint::from(1u8);
        let m = &expected << (nu + 1) as usize;
        let word = aggregate(&[a(1u64, 0)], &[Some(m)], nu, bits)
            .unwrap()
            .unwrap();
        assert_eq!(word.bits, bits);
        assert_eq!(BigUint::from_bytes_be(&word.to_be_bytes()), expected);
    }
}
