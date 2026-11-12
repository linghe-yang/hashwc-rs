use hashrand::{Behavior, Context, Event, Parameters, Request};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};
use tokio::sync::mpsc;
fn free_base(n: usize) -> u16 {
    for _ in 0..100 {
        let r = crypto::random().unwrap();
        // Keep test listeners below Linux ephemeral client ports (32768+).
        let base = 20000 + u16::from_le_bytes([r[0], r[1]]) % 10000;
        let held = (0..config::SERVICE_COUNT * n)
            .map(|i| std::net::TcpListener::bind(("127.0.0.1", base + i as u16)))
            .collect::<std::io::Result<Vec<_>>>();
        if held.is_ok() {
            return base;
        }
    }
    panic!("no free local port range")
}
pub fn nodes(weights: &[u64], threshold: u64) -> Vec<config::Node> {
    let base = free_base(weights.len());
    let session = crypto::random().unwrap();
    (0..weights.len())
        .map(|id| {
            let mut node = config::Node::new();
            node.id = id;
            node.num_nodes = weights.len();
            node.session_id = session;
            node.weights = weights
                .iter()
                .copied()
                .map(sdc_types::Weight::from)
                .collect();
            node.weight_threshold = Some(sdc_types::Weight::from(threshold));
            for p in 0..weights.len() {
                node.net_map
                    .insert(p, format!("127.0.0.1:{}", base + p as u16));
                node.sk_map.insert(
                    p,
                    crypto::hash(
                        b"test-only/key",
                        &[
                            &session,
                            &(id.min(p) as u64).to_le_bytes(),
                            &(id.max(p) as u64).to_le_bytes(),
                        ],
                    )
                    .to_vec(),
                );
            }
            node
        })
        .collect()
}
async fn run(
    weights: &[u64],
    threshold: u64,
    params: Parameters,
    silent: Option<usize>,
    bad: Option<(usize, Behavior)>,
) {
    let mut handles = vec![];
    let mut inputs = vec![];
    let mut outputs = vec![];
    for node in nodes(weights, threshold) {
        if Some(node.id) == silent {
            continue;
        }
        let (input, rx) = mpsc::channel(1);
        let (tx, output) = mpsc::channel(4096);
        let behavior = bad
            .filter(|(id, _)| *id == node.id)
            .map_or(Behavior::Honest, |(_, b)| b);
        handles.push(Context::spawn_with_behavior(node, params.clone(), behavior, rx, tx).unwrap());
        inputs.push(input);
        outputs.push(output);
    }
    for input in &inputs {
        input.send(Request::Start).await.unwrap();
    }
    let collected = tokio::time::timeout(Duration::from_secs(45), async {
        let mut result = vec![];
        for output in &mut outputs {
            let mut trace = vec![];
            loop {
                let event = output.recv().await.expect("service closed");
                if let Event::Failed { reason } = &event {
                    panic!("{reason}");
                }
                let done = matches!(event, Event::Complete);
                trace.push(event);
                if done {
                    break;
                }
            }
            result.push(trace);
        }
        result
    })
    .await
    .expect("HashRand TCP protocol timed out");
    let mut reference = None;
    for trace in collected {
        let mut coins = BTreeMap::new();
        let mut gathered = BTreeSet::new();
        let mut released = BTreeSet::new();
        let mut seeds = BTreeSet::new();
        let mut frozen = BTreeSet::new();
        let mut committees = BTreeMap::new();
        for event in trace {
            match event {
                Event::Gathered { batch, .. } => {
                    gathered.insert(batch);
                }
                Event::SeedRelease {
                    target_batch,
                    source_batch,
                    source_slot,
                } => {
                    assert_eq!(
                        params.seed_source(target_batch, weights.len()),
                        Some((source_batch, source_slot))
                    );
                    released.insert(target_batch);
                }
                Event::SeedOpened { target_batch, .. } => {
                    assert!(released.contains(&target_batch));
                    seeds.insert(target_batch);
                }
                Event::Committee {
                    batch,
                    sampled,
                    dealers,
                } => {
                    assert!(gathered.contains(&batch));
                    assert_eq!(sampled, !params.checkpoint(batch, weights.len()));
                    assert!(!dealers.is_empty());
                    if sampled {
                        assert!(seeds.contains(&batch));
                    } else {
                        assert_eq!(dealers, (0..weights.len()).collect::<Vec<_>>());
                    }
                    committees.insert(batch, dealers);
                }
                Event::Frozen { batch } => {
                    assert!(committees.contains_key(&batch));
                    frozen.insert(batch);
                }
                Event::Beacon {
                    batch,
                    index,
                    value,
                } => {
                    assert!(frozen.contains(&batch));
                    if batch > 0 {
                        assert_eq!(
                            coins.keys().filter(|&&(b, _)| b == batch - 1).count(),
                            params.batch_size
                        );
                    }
                    assert_eq!(value.bits, params.output_bits);
                    assert!(coins.insert((batch, index), value).is_none());
                }
                Event::Reconstructed {
                    dealer, rejected, ..
                } => {
                    if bad.is_some_and(|(id, b)| {
                        id == dealer && matches!(b, Behavior::InvalidPolynomial)
                    }) {
                        assert!(rejected);
                    } else {
                        assert!(!rejected);
                    }
                }
                _ => {}
            }
        }
        assert_eq!(coins.len(), params.batch_size * params.batches);
        assert_eq!(committees.len(), params.batches);
        if params.batches == 1 {
            assert!(seeds.is_empty());
        }
        if let Some(r) = &reference {
            assert_eq!(r, &coins);
        } else {
            reference = Some(coins);
        }
    }
    for handle in handles {
        handle.shutdown().await.unwrap();
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn four_equal_parties_single_coin_never_use_anytrust() {
    run(
        &[1; 4],
        1,
        Parameters {
            rounding_bits: 24,
            ..Parameters::default()
        },
        None,
        None,
    )
    .await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn four_weighted_parties_batched_beacon_uses_delayed_previous_seed_and_refills_pool() {
    run(
        &[3, 2, 4, 3],
        4,
        Parameters {
            batch_size: 2,
            batches: 6,
            output_bits: 128,
            rounding_bits: 24,
            ..Parameters::default()
        },
        None,
        None,
    )
    .await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_honest_of_four_terminate_despite_silent_weight_below_threshold() {
    run(
        &[3; 4],
        4,
        Parameters {
            batch_size: 2,
            batches: 2,
            rounding_bits: 24,
            ..Parameters::default()
        },
        Some(3),
        None,
    )
    .await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn valid_merkle_proofs_do_not_hide_an_invalid_dealer_polynomial() {
    run(
        &[3; 4],
        4,
        Parameters {
            batch_size: 2,
            batches: 2,
            rounding_bits: 24,
            ..Parameters::default()
        },
        None,
        Some((3, Behavior::InvalidPolynomial)),
    )
    .await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn withholding_all_recovery_tickets_does_not_block_honest_output() {
    run(
        &[3; 4],
        4,
        Parameters {
            batch_size: 2,
            batches: 2,
            rounding_bits: 24,
            ..Parameters::default()
        },
        None,
        Some((3, Behavior::WithholdRecovery)),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn short_root_single_coin_preserves_silence_and_invalid_dealer_liveness() {
    let params = Parameters {
        rounding_bits: 24,
        ..Parameters::default()
    };
    run(&[3, 2, 4, 3], 4, params.clone(), Some(1), None).await;
    run(
        &[3; 4],
        4,
        params.clone(),
        None,
        Some((3, Behavior::InvalidPolynomial)),
    )
    .await;
    run(
        &[3; 4],
        4,
        params,
        None,
        Some((3, Behavior::WithholdRecovery)),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn integer_boundary_silent_faults_still_allow_single_coin() {
    for (weights, t, silent) in [
        ([1u64; 4], 2, 0),
        ([1, 1, 1, 2], 2, 0),
        ([1, 2, 2, 2], 3, 1),
        ([2; 4], 3, 1),
    ] {
        run(
            &weights,
            t,
            Parameters {
                rounding_bits: 24,
                ..Parameters::default()
            },
            Some(silent),
            None,
        )
        .await;
    }
}
