use crate::{Context, Event, Parameters, Request};
use std::time::Duration;
use tokio::sync::mpsc;
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn clean_four_party_tight_sampling_completes_with_both_list_transports_and_weighted_silence()
{
    use crate::protocol::parameters::ListBroadcast;
    for list_broadcast in [ListBroadcast::FixedChunksV1, ListBroadcast::CodedV1] {
        let mut handles = vec![];
        let mut inputs = vec![];
        let mut outputs = vec![];
        for node in super::nodes(&[1, 2, 4, 5], 4, free_base(4))
            .into_iter()
            .skip(1)
        {
            let (input, rx) = mpsc::channel(1);
            let (tx, output) = mpsc::channel(128);
            handles.push(
                Context::spawn(
                    node,
                    Parameters {
                        short_root_rbc: true,
                        reuse_local_dealer: true,
                        list_broadcast,
                        ..Parameters::default()
                    },
                    rx,
                    tx,
                )
                .unwrap(),
            );
            inputs.push(input);
            outputs.push(output);
        }
        for input in &inputs {
            input.send(Request::Start).await.unwrap();
        }
        let coins = tokio::time::timeout(Duration::from_secs(30), async {
            let mut coins = vec![];
            for mut out in outputs {
                let mut frozen = false;
                loop {
                    match out.recv().await.expect("clean service stopped") {
                        Event::Frozen { .. } => frozen = true,
                        Event::Coin { value, .. } => {
                            assert!(frozen);
                            coins.push(value);
                            break;
                        }
                        Event::Failed { reason } => panic!("{reason}"),
                        _ => {}
                    }
                }
            }
            coins
        })
        .await
        .expect("clean four-party run did not terminate");
        assert_eq!(coins.len(), 3);
        assert!(coins.iter().all(|c| *c == coins[0]));
        for handle in handles {
            handle.shutdown().await.unwrap();
        }
    }
}
fn free_base(n: usize) -> u16 {
    for _ in 0..100 {
        let random = crypto::random().unwrap();
        let base = 20000 + u16::from_le_bytes([random[0], random[1]]) % 30000;
        let held = (0..config::SERVICE_COUNT * n)
            .map(|i| std::net::TcpListener::bind(("127.0.0.1", base + i as u16)))
            .collect::<std::io::Result<Vec<_>>>();
        if held.is_ok() {
            return base;
        }
    }
    panic!("no local port range available")
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn actual_node_channels_and_seven_tcp_services_complete_with_a_silent_peer() {
    complete_with_silent_peer(1, false, crate::RecoveryMode::Sampled, false, false).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multibit_channels_complete_with_a_silent_peer() {
    complete_with_silent_peer(128, false, crate::RecoveryMode::Sampled, false, false).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn short_root_tcp_services_complete_with_silence_and_optional_coded_lists() {
    for mode in [crate::RecoveryMode::Sampled, crate::RecoveryMode::Auto] {
        complete_with_silent_peer(1, true, mode, false, false).await;
    }
}
async fn complete_with_silent_peer(
    output_bits: u32,
    short_root_rbc: bool,
    mode: crate::RecoveryMode,
    reuse_verified_material: bool,
    compact_binaa: bool,
) {
    complete_with_circuit(
        output_bits,
        short_root_rbc,
        mode,
        reuse_verified_material,
        compact_binaa,
        crate::CircuitMode::Legacy,
    )
    .await;
}
async fn complete_with_circuit(
    output_bits: u32,
    short_root_rbc: bool,
    mode: crate::RecoveryMode,
    reuse_verified_material: bool,
    compact_binaa: bool,
    circuit_mode: crate::CircuitMode,
) {
    let configs = super::nodes(&[1; 7], 2, free_base(7));
    let mut handles = vec![];
    let mut inputs = vec![];
    let mut outputs = vec![];
    // Party 6 is silent: B=1 < T=2. These are Rust module tests, not benchmark processes.
    for node in configs.into_iter().take(6) {
        let material = reuse_verified_material && node.id % 2 == 0; // Local option interoperates with uncached peers.
        let (input, rx) = mpsc::channel(1);
        let (tx, output) = mpsc::channel(128);
        handles.push(
            Context::spawn(
                node,
                Parameters {
                    short_root_rbc,
                    compact_binaa,
                    circuit_mode,
                    reuse_verified_material: material,
                    recovery_mode: mode,
                    reuse_local_dealer: short_root_rbc,
                    coverage_bits: if short_root_rbc { 40 } else { 8 },
                    rounding_bits: 24,
                    output_bits,
                    ..Parameters::default()
                },
                rx,
                tx,
            )
            .unwrap(),
        );
        inputs.push(input);
        outputs.push(output);
    }
    for input in &inputs {
        input.send(Request::Start).await.unwrap();
    }
    let bits = tokio::time::timeout(Duration::from_secs(45), async {
        let mut bits = vec![];
        for mut out in outputs {
            let mut frozen = false;
            loop {
                match out.recv().await.expect("service ended before output") {
                    Event::Frozen { .. } => {
                        assert!(!frozen);
                        frozen = true;
                    }
                    Event::Coin { value, .. } => {
                        assert!(frozen);
                        assert_eq!(value.bits, output_bits);
                        value.validate().unwrap();
                        bits.push(value);
                        break;
                    }
                    Event::Failed { reason } => panic!("{reason}"),
                    _ => {}
                }
            }
        }
        bits
    })
    .await
    .expect("coin services did not complete");
    assert_eq!(bits.len(), 6);
    assert!(bits.windows(2).all(|x| x[0] == x[1]));
    for handle in handles {
        handle.shutdown().await.unwrap();
    }
}
#[test]
fn upstream_node_roundtrip_and_local_remote_port_plans() {
    let nodes = super::nodes(&[1; 4], 1, 20000);
    let node: config::Node =
        serde_json::from_slice(&serde_json::to_vec(&nodes[0]).unwrap()).unwrap();
    let p = config::Ports::new(&node, None).unwrap();
    assert_eq!(
        p.node(&node, config::Service::Recovery).unwrap().net_map[&3],
        "127.0.0.1:20023"
    );
    let mut remote = node.clone();
    for i in 0..4 {
        remote.net_map.insert(i, format!("10.0.0.{}:20000", i + 1));
    }
    let p = config::Ports::new(&remote, None).unwrap();
    for i in 0..4 {
        assert!(p.node(&remote, config::Service::Gather).unwrap().net_map[&i].ends_with(":20008"));
    }
    assert!(config::Ports::new(&node, Some(1)).is_err());
    assert!(config::Ports::new(&node, Some(10000)).is_err());
    let mut aliases = node;
    aliases.net_map.insert(1, "127.0.0.2:20000".into());
    assert!(config::Ports::new(&aliases, None).is_err());
}
#[test]
fn options_bind_every_primitive_context_and_contribution_range() {
    let node = super::nodes(&[1; 4], 1, 20000).remove(0);
    let a = Parameters::default();
    let s = a.setup(&node).unwrap();
    let mut b = a.clone();
    b.rounding_bits += 1;
    assert_ne!(
        a.bound_node(&node, &s).session_id,
        b.bound_node(&node, &s).session_id
    );
    b = a.clone();
    b.coverage_bits += 1;
    assert_ne!(a.context_id(&node, &s), b.context_id(&node, &s));
    b = a.clone();
    b.epoch += 1;
    assert_ne!(a.context_id(&node, &s), b.context_id(&node, &s));
    for bits in [1, 6, 7, 8, 64, 252] {
        b.rounding_bits = bits;
        for _ in 0..16 {
            assert!(num_bigint::BigUint::from_bytes_be(&b.sample_message().unwrap()) < b.range());
        }
    }
    b.rounding_bits = 253;
    assert!(b.validate(&node).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_event_consumer_does_not_block_protocol_or_shutdown() {
    let mut handles = vec![];
    let mut outputs = vec![];
    for node in super::nodes(&[1; 4], 1, free_base(4)) {
        let (input, rx) = mpsc::channel(1);
        let (tx, output) = mpsc::channel(1);
        let service = Context::spawn(
            node,
            Parameters {
                coverage_bits: 4,
                rounding_bits: 8,
                ..Parameters::default()
            },
            rx,
            tx,
        )
        .unwrap();
        input.send(Request::Start).await.unwrap();
        handles.push(service);
        outputs.push(output);
    }
    // Fill the application event channels while the seven network services keep working.
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if outputs.iter().all(|r| !r.is_empty()) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    for service in handles {
        tokio::time::timeout(Duration::from_secs(3), service.shutdown())
            .await
            .expect("blocked behind application events")
            .unwrap();
    }
}

#[test]
fn multibit_parameters_bind_context_precision_and_full_sampling_range() {
    use num_bigint::BigUint;
    let node = super::nodes(&[1; 4], 1, 20000).remove(0);
    let base = Parameters::default();
    let setup = base.setup(&node).unwrap();
    for (nu, bits) in [(64, 128), (64, 189), (1, 252)] {
        let p = Parameters {
            rounding_bits: nu,
            output_bits: bits,
            ..base.clone()
        };
        p.validate(&node).unwrap();
        assert_ne!(base.context_id(&node, &setup), p.context_id(&node, &setup));
        assert_eq!(
            BigUint::from_bytes_be(&p.precision(4).denominator.0.to_bytes_be()),
            p.range() * 4u8
        );
        let mut high_seen = false;
        for _ in 0..64 {
            let m = BigUint::from_bytes_be(&p.sample_message().unwrap());
            assert!(m < p.range());
            high_seen |= m.bits() == (nu + bits + 1) as u64;
        }
        // Probability of a false failure is 2^-64; catches accidentally retaining binary sampling.
        assert!(high_seen);
    }
    for (nu, bits) in [(64, 190), (1, 253), (0, 128), (64, 0), (u32::MAX, 1)] {
        assert!(Parameters::validate_widths(nu, bits).is_err());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_honest_parties_finish_despite_active_recovery_stress_peer() {
    let mut handles = vec![];
    let mut inputs = vec![];
    let mut outputs = vec![];
    for node in super::nodes(&[3; 4], 4, free_base(4)) {
        let behavior = if node.id == 3 {
            crate::Behavior::RecoveryStress
        } else {
            crate::Behavior::Honest
        };
        let (input, rx) = mpsc::channel(1);
        let (tx, output) = mpsc::channel(128);
        handles.push(
            Context::spawn_with_behavior(
                node,
                Parameters {
                    output_bits: 128,
                    ..Parameters::default()
                },
                behavior,
                rx,
                tx,
            )
            .unwrap(),
        );
        inputs.push(input);
        outputs.push(output);
    }
    for input in &inputs {
        input.send(Request::Start).await.unwrap();
    }
    let coins = tokio::time::timeout(Duration::from_secs(45), async {
        let mut coins = vec![];
        for out in outputs.iter_mut().take(3) {
            loop {
                match out.recv().await.unwrap() {
                    Event::Coin { value, .. } => {
                        coins.push(value);
                        break;
                    }
                    Event::Failed { reason } => panic!("{reason}"),
                    _ => {}
                }
            }
        }
        coins
    })
    .await
    .expect("honest nodes blocked by Byzantine recovery omission");
    assert_eq!(coins.len(), 3);
    assert!(coins.windows(2).all(|x| x[0] == x[1]));
    for handle in handles {
        handle.shutdown().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shared_material_tcp_mixed_local_options_and_silent_peer() {
    for mode in [crate::RecoveryMode::Sampled, crate::RecoveryMode::Auto] {
        complete_with_silent_peer(1, true, mode, true, false).await;
    }
}
#[test]
fn shared_material_is_local_and_preserves_protocol_context_and_defaults() {
    let node = super::nodes(&[3; 4], 4, 20000).remove(0);
    let p = Parameters::default();
    assert!(!p.reuse_verified_material);
    let setup = p.setup(&node).unwrap();
    let mut optimized = p.clone();
    optimized.reuse_verified_material = true;
    assert_eq!(
        p.context_id(&node, &setup),
        optimized.context_id(&node, &setup)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn compact_binaa_tcp_with_silent_peer_and_both_recovery_modes() {
    for mode in [crate::RecoveryMode::Sampled, crate::RecoveryMode::Auto] {
        complete_with_silent_peer(1, true, mode, true, true).await;
    }
}

#[test]
fn compact_binaa_is_version_bound_and_rejects_more_than_91_parties() {
    let node = super::nodes(&[3; 4], 4, 20000).remove(0);
    let p = Parameters::default();
    assert!(!p.compact_binaa);
    let setup = p.setup(&node).unwrap();
    let mut compact = p.clone();
    compact.compact_binaa = true;
    assert_ne!(
        p.context_id(&node, &setup),
        compact.context_id(&node, &setup)
    );
    assert!(
        compact
            .validate(&super::nodes(&[3; 91], 91, 20000).remove(0))
            .is_ok()
    );
    assert!(
        compact
            .validate(&super::nodes(&[3; 92], 92, 20000).remove(0))
            .is_err()
    );
    assert!(
        p.validate(&super::nodes(&[3; 92], 92, 20000).remove(0))
            .is_ok()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn optimized_circuit_tcp_with_silent_peer_and_both_recovery_modes() {
    for mode in [crate::RecoveryMode::Sampled, crate::RecoveryMode::Auto] {
        complete_with_circuit(1, true, mode, true, true, crate::CircuitMode::OptimizedV1).await;
    }
}

#[test]
fn compiler_version_preserves_legacy_and_binds_every_primitive_context() {
    let node = super::nodes(&[3; 8], 8, 20000).remove(0);
    let default: Parameters = serde_json::from_str("{}").unwrap();
    assert_eq!(default.circuit_mode, crate::CircuitMode::CleanV1);
    let old: Parameters = serde_json::from_str(r#"{"circuit_mode":"legacy"}"#).unwrap();
    assert_eq!(old.circuit_mode, crate::CircuitMode::Legacy);
    let optimized = Parameters {
        circuit_mode: crate::CircuitMode::OptimizedV1,
        ..old.clone()
    };
    let a = old.setup(&node).unwrap();
    let b = optimized.setup(&node).unwrap();
    assert_eq!(
        a.id(),
        wcss::Setup::new(config::policy(&node).unwrap(), wcss::Limits::default())
            .unwrap()
            .id()
    );
    assert_eq!(
        b.id(),
        wcss::Setup::new_optimized(config::policy(&node).unwrap(), wcss::Limits::default())
            .unwrap()
            .id()
    );
    assert_ne!(old.context_id(&node, &a), optimized.context_id(&node, &b));
    assert!(b.circuit().gates().len() < a.circuit().gates().len());
    assert_eq!(b.circuit().policy().encode(), a.circuit().policy().encode());
    let new_precision = optimized.precision(node.num_nodes);
    let old_precision = old.precision(node.num_nodes);
    assert_eq!(new_precision.numerator, old_precision.numerator);
    assert_eq!(new_precision.denominator, old_precision.denominator);
    assert!(serde_json::from_str::<Parameters>(r#"{"circuit_mode":"optimized-v2"}"#).is_err());
}

// Keep this matrix explicitly at four nodes: the older optimized TCP helper uses seven.
async fn optimized_four_node_case(
    weights: [u64; 4],
    threshold: u64,
    mode: crate::RecoveryMode,
    output_bits: u32,
    silent: Option<usize>,
    stress: Option<usize>,
) {
    assert!(silent.is_none() || stress.is_none());
    if let Some(id) = silent.or(stress) {
        assert!(weights[id] < threshold, "fault weight must satisfy B < T");
    }
    eprintln!(
        "four-node case: weights={weights:?}, T={threshold}, mode={mode:?}, bits={output_bits}, silent={silent:?}, stress={stress:?}"
    );
    let mut handles = vec![];
    let mut inputs = vec![];
    let mut outputs = vec![];
    for node in super::nodes(&weights, threshold, free_base(4)) {
        let id = node.id;
        if silent == Some(id) {
            continue;
        }
        let (input, rx) = mpsc::channel(1);
        let (tx, output) = mpsc::channel(128);
        handles.push(
            Context::spawn_with_behavior(
                node,
                Parameters {
                    circuit_mode: crate::CircuitMode::OptimizedV1,
                    short_root_rbc: true,
                    compact_binaa: true,
                    reuse_local_dealer: true,
                    reuse_verified_material: true,
                    recovery_mode: mode,
                    bulk_block_bytes: 128.into(),
                    output_bits,
                    ..Parameters::default()
                },
                if stress == Some(id) {
                    crate::Behavior::RecoveryStress
                } else {
                    crate::Behavior::Honest
                },
                rx,
                tx,
            )
            .unwrap(),
        );
        inputs.push(input);
        outputs.push((id, output));
    }
    for input in &inputs {
        input.send(Request::Start).await.unwrap();
    }
    tokio::time::timeout(Duration::from_secs(45), async {
        if let Some(stress_id) = stress {
            let (_, out) = outputs.iter_mut().find(|(id, _)| *id == stress_id).unwrap();
            loop {
                match out
                    .recv()
                    .await
                    .expect("stress node stopped before sending an attack")
                {
                    Event::AdversarialTerminal { recipients, .. } => {
                        assert!(recipients > 0);
                        break;
                    }
                    Event::Failed { reason } => panic!("stress node failed: {reason}"),
                    _ => {}
                }
            }
        }
        let mut coins = vec![];
        for (id, out) in &mut outputs {
            if stress == Some(*id) {
                continue;
            }
            let mut frozen = false;
            loop {
                match out.recv().await.expect("node stopped before coin") {
                    Event::Frozen { .. } => {
                        assert!(!frozen, "duplicate Freeze at party {id}");
                        frozen = true;
                    }
                    Event::Coin { value, .. } => {
                        assert!(frozen, "coin before Freeze at party {id}");
                        assert_eq!(value.bits, output_bits);
                        value.validate().unwrap();
                        coins.push(value);
                        break;
                    }
                    Event::Failed { reason } => panic!("party {id}: {reason}"),
                    _ => {}
                }
            }
        }
        assert_eq!(coins.len(), if silent.or(stress).is_some() { 3 } else { 4 });
        assert!(
            coins.windows(2).all(|c| c[0] == c[1]),
            "honest coin disagreement"
        );

        // This predicate requires *all* dealers; never demand it of a silent/bad dealer.
        if silent.is_none() && stress.is_none() {
            loop {
                let mut complete = true;
                for input in &inputs {
                    let (reply, mut rx) = mpsc::unbounded_channel();
                    input.send(Request::Inspect { reply }).await.unwrap();
                    let progress = rx.recv().await.expect("missing inspection");
                    assert!(progress.output_observed);
                    complete &= progress.all_honest_services_complete;
                }
                if complete {
                    break;
                }
                // Observation polling only; protocol progress has no timer assumption.
                tokio::task::yield_now().await;
            }
        }
        for (id, out) in &mut outputs {
            if stress == Some(*id) {
                continue;
            }
            while let Ok(event) = out.try_recv() {
                match event {
                    Event::Coin { .. } => panic!("duplicate coin at party {id}"),
                    Event::Frozen { .. } => panic!("duplicate Freeze at party {id}"),
                    Event::Failed { reason } => panic!("party {id}: {reason}"),
                    _ => {}
                }
            }
        }
    })
    .await
    .expect("four-node correctness/service test timed out");
    for handle in handles {
        tokio::time::timeout(Duration::from_secs(5), handle.shutdown())
            .await
            .expect("shutdown timed out")
            .unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn optimized_four_nodes_all_honest_finish_coin_and_services() {
    for (weights, threshold) in [([3; 4], 4), ([3, 4, 4, 4], 5), ([9, 10, 11, 12], 14)] {
        for bits in [1, 128] {
            optimized_four_node_case(
                weights,
                threshold,
                crate::RecoveryMode::Auto,
                bits,
                None,
                None,
            )
            .await;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn optimized_four_nodes_tolerate_each_silent_identity() {
    for mode in [crate::RecoveryMode::Auto, crate::RecoveryMode::Sampled] {
        for (weights, threshold) in [([3; 4], 4), ([3, 4, 4, 4], 5)] {
            for silent in 0..4 {
                optimized_four_node_case(weights, threshold, mode, 1, Some(silent), None).await;
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn optimized_four_nodes_tolerate_each_active_recovery_stress_identity() {
    for mode in [crate::RecoveryMode::Auto, crate::RecoveryMode::Sampled] {
        for stress in 0..4 {
            optimized_four_node_case([3; 4], 4, mode, 128, None, Some(stress)).await;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rounded_threshold_boundary_tolerates_maximum_silent_weight() {
    for (weights, t, silent) in [
        ([1u64; 4], 2, 0),
        ([1, 1, 1, 2], 2, 0),
        ([1, 2, 2, 2], 3, 1),
        ([2; 4], 3, 1),
    ] {
        optimized_four_node_case(
            weights,
            t,
            crate::RecoveryMode::Sampled,
            1,
            Some(silent),
            None,
        )
        .await;
    }
    optimized_four_node_case([1; 4], 2, crate::RecoveryMode::Sampled, 1, None, Some(3)).await;
}
