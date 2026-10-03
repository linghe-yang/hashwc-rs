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
    use crate::aggregate::aggregate;
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
