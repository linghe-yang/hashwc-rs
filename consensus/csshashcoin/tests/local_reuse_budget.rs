use wiawvss::blocksize::Model;

fn node(weights: &[String], threshold: &str) -> config::Node {
    let mut n = config::Node::new();
    n.id = 0;
    n.num_nodes = weights.len();
    n.session_id = [7; 32];
    n.weights = weights.iter().map(|w| w.parse().unwrap()).collect();
    n.weight_threshold = Some(threshold.parse().unwrap());
    for i in 0..weights.len() {
        n.net_map.insert(i, format!("127.0.0.1:{}", 22000 + i));
        n.sk_map.insert(i, vec![9; 32]);
    }
    n
}
fn model(n: &config::Node, s: &wcss::Setup, loads: Vec<usize>, pvr: bool) -> Model {
    let c = wavid::Codec::new(
        &n.weighted_membership().unwrap(),
        sdc_types::InstanceId::new(0, Some(0), 0),
        [0; 32],
        if pvr {
            wiawvss::Public::encoded_len(s)
        } else {
            wiawvss::compact::Public::encoded_len(s)
        },
    )
    .unwrap();
    Model::new(s, &c, loads, pvr).unwrap()
}

#[test]
fn reuse_binds_context_and_uses_only_certain_sampling_savings() {
    let n = node(&["1", "2", "4", "5"].map(str::to_string), "4");
    let off = whcc::Parameters {
        coverage_bits: 1,
        bulk_block_bytes: 128.into(),
        ..whcc::Parameters::default()
    };
    let on = whcc::Parameters {
        reuse_local_dealer: true,
        ..off.clone()
    };
    let (s, a, old) = off.prepare(&n).unwrap();
    let (_, b, new) = on.prepare(&n).unwrap();
    assert_ne!(a.context_id(&n, &s), b.context_id(&n, &s));
    let quotas = a.sampling(&s).unwrap().quotas;
    assert!(quotas.iter().any(|&d| d < n.num_nodes));
    let loads = quotas
        .iter()
        .map(|&d| d - usize::from(d == n.num_nodes))
        .collect();
    assert_eq!(
        new.chosen.variable_ledger_bytes,
        model(&n, &s, loads, true)
            .evaluate(128)
            .unwrap()
            .variable_ledger_bytes
    );
    assert!(new.chosen.variable_ledger_bytes <= old.chosen.variable_ledger_bytes);
    let off = csshashcoin::Parameters {
        rbc_block_bytes: 128.into(),
        ..csshashcoin::Parameters::default()
    };
    let on = csshashcoin::Parameters {
        reuse_local_dealer: true,
        ..off.clone()
    };
    let (_, a, old) = off.prepare(&n).unwrap();
    let (_, b, new) = on.prepare(&n).unwrap();
    assert_ne!(a.bound_node(&n).session_id, b.bound_node(&n).session_id);
    // Bulk falls from (n^2-1) bundles to n(n-1), independent of weights.
    assert_eq!(
        old.chosen.variable_ledger_bytes * 4,
        new.chosen.variable_ledger_bytes * 5
    );
}

#[test]
fn aptos_offline_budgets_keep_guarantees_separate_from_expectations() {
    #[derive(serde::Deserialize)]
    struct Case {
        n: usize,
        weights: Vec<String>,
        threshold: String,
    }
    let cases: Vec<Case> = serde_json::from_str(include_str!(
        "../../wiawvss/tests/fixtures/clean-aptos.json"
    ))
    .unwrap();
    for c in cases {
        let n = node(&c.weights, &c.threshold);
        let (s, _, old) = whcc::Parameters::default().prepare(&n).unwrap();
        let (_, p, new) = whcc::Parameters {
            reuse_local_dealer: true,
            ..whcc::Parameters::default()
        }
        .prepare(&n)
        .unwrap();
        let quotas = p.sampling(&s).unwrap().quotas;
        let edges = quotas.iter().sum::<usize>();
        let certain = quotas.iter().filter(|&&d| d == c.n).count();
        let m = model(&n, &s, quotas.clone(), true);
        let at_new = m.evaluate(new.chosen.block_bytes).unwrap();
        // E[remote_i] = d_i (1-1/n). Report the exact rational first;
        // the optimizer never uses this expectation as a guaranteed saving.
        let expected_num =
            at_new.variable_ledger_bytes * c.n as u128 - at_new.retrieval_bundle_bytes;
        let expected = expected_num as f64 / c.n as f64;
        let (_, _, warm_old) = csshashcoin::Parameters::default().prepare(&n).unwrap();
        let (ws, _, warm_new) = csshashcoin::Parameters {
            reuse_local_dealer: true,
            ..csshashcoin::Parameters::default()
        }
        .prepare(&n)
        .unwrap();
        assert_eq!(s.id(), ws.id());
        assert!(new.chosen.variable_ledger_bytes <= old.chosen.variable_ledger_bytes);
        assert!(warm_new.chosen.variable_ledger_bytes < warm_old.chosen.variable_ledger_bytes);
        assert!(expected <= new.chosen.variable_ledger_bytes as f64);
        let k = new.chosen.block_bytes;
        // Different actual self-hit subsets cannot exceed the chosen public
        // bound. Checking extremal loads suffices because the ledger is linear.
        let all_hit = quotas.iter().map(|&d| d - 1).collect();
        let maximum = quotas.iter().map(|&d| d - usize::from(d == c.n)).collect();
        let best = model(&n, &s, all_hit, true).evaluate(k).unwrap();
        let worst = model(&n, &s, maximum, true).evaluate(k).unwrap();
        assert!(best.variable_ledger_bytes as f64 <= expected);
        assert_eq!(
            worst.variable_ledger_bytes,
            new.chosen.variable_ledger_bytes
        );
        println!(
            "LOCAL_REUSE_BUDGET,{}",
            serde_json::json!({
                "n":c.n,"assignment_edges":edges,"certain_self_edges":certain,
                "expected_self_edges":edges as f64/c.n as f64,
                "whcc_before":old.chosen,"whcc_after_public_bound":new.chosen,
                "whcc_expected_variable_bytes":expected,
                "whcc_expected_exact_numerator":expected_num,"denominator":c.n,
                "warmup_before":warm_old.chosen,"warmup_after":warm_new.chosen,
                "scope":"full normal service bulk + private receipts; excludes controls, tokens, terminals, faults, TCP/IP and retransmissions"
            })
        );
    }
}
