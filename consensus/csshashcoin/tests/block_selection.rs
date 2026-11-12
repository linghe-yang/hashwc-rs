use csshashcoin::{Behavior, Parameters};
use wiawvss::blocksize::Model;

fn node(weights: &[String], threshold: &str) -> config::Node {
    let mut node = config::Node::new();
    node.num_nodes = weights.len();
    node.id = 0;
    node.session_id = [7; 32];
    node.weights = weights.iter().map(|w| w.parse().unwrap()).collect();
    node.weight_threshold = Some(threshold.parse().unwrap());
    for i in 0..weights.len() {
        node.net_map.insert(i, format!("127.0.0.1:{}", 22000 + i));
        node.sk_map.insert(i, vec![9; 32]);
    }
    node
}

#[test]
fn runtime_manifests_and_contexts_bind_the_resolved_choice() {
    let node = node(&vec!["3".to_string(); 4], "4");
    let wp = whcc::Parameters::default();
    let w = whcc::State::new(&node, wp.clone()).unwrap();
    let b = w.block_selection.chosen.block_bytes;
    assert_eq!(w.params.bulk_coding().block_bytes, b);
    assert!(
        w.dealers
            .iter()
            .all(|d| d.codec.parameters().block_bytes == b)
    );
    assert_eq!(w.context_id, wp.context_id(&node, w.setup()));
    let fixed = whcc::Parameters {
        bulk_block_bytes: b.into(),
        ..wp.clone()
    };
    assert_ne!(w.context_id, fixed.context_id(&node, w.setup()));
    let other = whcc::Parameters {
        bulk_block_bytes: (if b == 32 { 34 } else { 32 }).into(),
        ..wp
    };
    assert_ne!(
        fixed.context_id(&node, w.setup()),
        other.context_id(&node, w.setup())
    );

    let p = Parameters::default();
    let state = csshashcoin::State::new(&node, p.clone(), Behavior::Honest).unwrap();
    let effective = state.parameters();
    let b = state.block_selection.chosen.block_bytes;
    assert_eq!(effective.coding().block_bytes, b);
    assert!(
        state
            .rbc_manifest()
            .iter()
            .all(|r| matches!(r,wrbc::Request::Register{coding,..} if coding.block_bytes==b))
    );
    assert_eq!(
        p.bound_node(&node).session_id,
        effective.bound_node(&node).session_id
    );
    let fixed = Parameters {
        rbc_block_bytes: b.into(),
        ..p.clone()
    };
    assert_ne!(
        fixed.bound_node(&node).session_id,
        effective.bound_node(&node).session_id
    );

    let mut other_node = node.clone();
    other_node.id = 3;
    other_node.session_id = [33; 32];
    assert_eq!(p.prepare(&other_node).unwrap().2.chosen.block_bytes, b);
    assert_eq!(
        w.params.prepare(&other_node).unwrap().2.chosen.block_bytes,
        w.block_selection.chosen.block_bytes
    );
}

#[test]
fn frozen_aptos_sizes_select_feasible_blocks_and_report_offline_budgets() {
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
    for case in cases {
        let node = node(&case.weights, &case.threshold);
        let start = std::time::Instant::now();
        let (s, wp, whcc) = whcc::Parameters::default().prepare(&node).unwrap();
        let whcc_prepare_ms = start.elapsed().as_secs_f64() * 1000.0;
        let runtime = whcc::State::new(&node, wp.clone()).unwrap();
        let expected = match case.n {
            16 => 220,
            31 => 669,
            46 => 1231,
            60 => 1810,
            _ => unreachable!(),
        };
        assert_eq!(runtime.sampling.edge_bound(), expected);
        let chunk_lengths = runtime.list_chunk_lengths();
        assert_eq!(chunk_lengths, vec![64; case.n]);
        let list_wire_bytes = 225u64
            * (case.n - 1) as u64
            * (2 * case.n + 1) as u64
            * chunk_lengths.iter().map(|l| (l / 64) as u64).sum::<u64>();
        let start = std::time::Instant::now();
        let (warm_s, p, warm) = Parameters::default().prepare(&node).unwrap();
        let warm_prepare_ms = start.elapsed().as_secs_f64() * 1000.0;
        // Coded-list ablation with the same short-root service and full remote
        // service: bundle chunks cost 177 B overhead, control frames cost 197 B.
        let old_coded_list_bytes: u64 = runtime
            .sampling
            .quotas
            .iter()
            .enumerate()
            .map(|(dealer, &d)| {
                let c = wavid::Codec::new(
                    &node.weighted_membership().unwrap(),
                    sdc_types::InstanceId::new(0, Some(dealer), 1),
                    [0; 32],
                    32 + 4 * d,
                )
                .unwrap();
                let bulk: u64 = (0..case.n)
                    .map(|owner| {
                        let raw = c.bundle_bytes(owner);
                        (case.n - usize::from(owner == dealer)) as u64
                            * (raw + 177 * raw.div_ceil(wavid::CHUNK_BYTES)) as u64
                    })
                    .sum();
                bulk + 3 * case.n as u64 * (case.n - 1) as u64 * 197
            })
            .sum();
        assert_eq!(s.id(), warm_s.id());
        assert!(whcc.chosen.feasible && warm.chosen.feasible);
        assert_eq!(wp.bulk_coding().block_bytes, whcc.chosen.block_bytes);
        assert_eq!(p.coding().block_bytes, warm.chosen.block_bytes);
        let models = [(true, &s, wp.bulk_coding()), (false, &warm_s, p.coding())]
            .into_iter()
            .map(|(pvr, s, coding)| {
                let codec = wavid::Codec::with_params(
                    &node.weighted_membership().unwrap(),
                    sdc_types::InstanceId::new(0, Some(0), 0),
                    [0; 32],
                    if pvr {
                        wiawvss::Public::encoded_len(s)
                    } else {
                        wiawvss::compact::Public::encoded_len(s)
                    },
                    coding,
                )
                .unwrap();
                // At these frozen Aptos sizes current sampled quotas are inspected
                // through the runtime state instead of assuming all recoveries.
                let loads = if pvr {
                    runtime.sampling.quotas.clone()
                } else {
                    vec![case.n; case.n]
                };
                Model::new(s, &codec, loads, pvr).unwrap()
            })
            .collect::<Vec<_>>();
        let w32 = models[0].evaluate(32).unwrap();
        let w1024 = models[0].evaluate(1024).unwrap();
        let c32 = models[1].evaluate(32).unwrap();
        let c1024 = models[1].evaluate(1024).unwrap();
        assert!(whcc.chosen.variable_ledger_bytes <= w1024.variable_ledger_bytes);
        assert!(
            warm.chosen.variable_ledger_bytes
                <= c32.variable_ledger_bytes.min(c1024.variable_ledger_bytes)
        );
        if case.n == 60 {
            assert!(!w32.feasible);
        }
        println!(
            "BLOCK_BUDGET,{}",
            serde_json::json!({"n":case.n,"whcc":whcc,"warmup":warm,
            "whcc_32":w32,"whcc_1024":w1024,"warmup_32":c32,"warmup_1024":c1024,
            "whcc_prepare_ms":whcc_prepare_ms,"warm_prepare_ms":warm_prepare_ms,
            "sampling_mode":wp.sampling_mode,"sampling_quotas":runtime.sampling.quotas,
            "assignment_edges":runtime.sampling.edge_bound(),"list_chunk_lengths":chunk_lengths,
            "list_full_service_wire_bytes":list_wire_bytes,
            "coded_list_full_service_wire_bytes":old_coded_list_bytes})
        );
    }
}
