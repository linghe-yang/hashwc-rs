use csshashcoin::Parameters;
use wcss::{Backend, CssProfile};

fn node(weights: &[u64], threshold: u64) -> config::Node {
    let mut n = config::Node::new();
    n.id = 0;
    n.num_nodes = weights.len();
    n.session_id = [31; 32];
    n.weights = weights
        .iter()
        .copied()
        .map(sdc_types::Weight::from)
        .collect();
    n.weight_threshold = Some(sdc_types::Weight::from(threshold));
    for i in 0..weights.len() {
        n.net_map.insert(i, format!("127.0.0.1:{}", 20000 + i));
        n.sk_map.insert(i, vec![29; 32]);
    }
    n
}

#[test]
fn both_coins_default_to_the_same_fixed_compiler_and_generated_backend() {
    for weights in [
        vec![3; 4],
        vec![2, 3, 4, 2, 3, 4, 2, 4],
        (0..60).map(|i| 295 + i % 11).collect(),
    ] {
        let n = node(&weights, weights.iter().sum::<u64>() / 3);
        let warm: Parameters = serde_json::from_str("{}").unwrap();
        let whcc: whcc::Parameters = serde_json::from_str("{}").unwrap();
        assert_eq!(warm.circuit_mode, CssProfile::CleanV1);
        assert_eq!(whcc.circuit_mode, CssProfile::CleanV1);
        let a = warm.setup(&n).unwrap();
        let b = whcc.setup(&n).unwrap();
        assert_eq!(a.id(), b.id());
        assert_eq!(a.circuit().encode(), b.circuit().encode());
        assert_eq!(a.backend(), Backend::GeneratedAnd0Or1);
        assert_eq!(a.correction_blocks(), b.correction_blocks());
        assert_eq!(
            a.circuit().policy().encode(),
            config::policy(&n).unwrap().encode()
        );
        assert_eq!(
            wiawvss::Public::encoded_len(&b) - wiawvss::compact::Public::encoded_len(&a),
            32 * a.pvr_wire_count()
        );
    }
}

#[test]
fn historical_modes_require_explicit_selection_and_bind_distinct_contexts() {
    let n = node(&[3; 8], 8);
    let mut ids = vec![];
    let mut sessions = vec![];
    for mode in [
        CssProfile::Legacy,
        CssProfile::OptimizedV1,
        CssProfile::CleanV1,
    ] {
        let warm = Parameters {
            circuit_mode: mode,
            ..Parameters::default()
        };
        let whcc = whcc::Parameters {
            circuit_mode: mode,
            ..whcc::Parameters::default()
        };
        let a = warm.setup(&n).unwrap();
        let b = whcc.setup(&n).unwrap();
        assert_eq!(a.id(), b.id());
        let decoded: Parameters =
            serde_json::from_slice(&serde_json::to_vec(&warm).unwrap()).unwrap();
        assert_eq!(decoded.setup(&n).unwrap().id(), a.id());
        ids.push(a.id());
        sessions.push(warm.bound_node(&n).session_id);
    }
    for i in 0..ids.len() {
        for j in 0..i {
            assert_ne!(ids[i], ids[j]);
            assert_ne!(sessions[i], sessions[j]);
        }
    }
    assert!(serde_json::from_str::<Parameters>(r#"{"circuit_mode":"auto"}"#).is_err());
    assert!(serde_json::from_str::<whcc::Parameters>(r#"{"circuit_mode":"auto"}"#).is_err());
}
