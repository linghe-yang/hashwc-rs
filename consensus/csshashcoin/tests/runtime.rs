use csshashcoin::{Behavior, Context, Event, Parameters, Request};
use std::{collections::BTreeMap, time::Duration};
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
    silent: Option<usize>,
    bad: Option<(usize, Behavior)>,
) {
    run_with_reuse(weights, threshold, silent, bad, false).await;
}
async fn run_with_reuse(
    weights: &[u64],
    threshold: u64,
    silent: Option<usize>,
    bad: Option<(usize, Behavior)>,
    reuse_local_dealer: bool,
) {
    let params = Parameters {
        rounding_bits: 24,
        output_bits: 128,
        reuse_local_dealer,
        ..Parameters::default()
    };
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
    for input in inputs {
        input.send(Request::Start).await.unwrap();
    }
    let traces = tokio::time::timeout(Duration::from_secs(45), async {
        let mut traces = vec![];
        for output in &mut outputs {
            let mut trace = vec![];
            let corrupt_dealer = bad
                .filter(|(_, b)| matches!(b, Behavior::InvalidAx))
                .map(|(d, _)| d);
            let mut complete = false;
            let mut observed_corrupt = corrupt_dealer.is_none();
            loop {
                let event = output.recv().await.expect("service closed");
                if let Event::Failed { reason } = &event {
                    panic!("{reason}");
                }
                complete |= matches!(event, Event::Complete);
                if let Event::Reconstructed { dealer, .. } = &event {
                    observed_corrupt |= Some(*dealer) == corrupt_dealer;
                }
                trace.push(event);
                // A dealer outside the coin support may finish after Complete.
                // Keep its service alive until this test actually observes rejection.
                if complete && observed_corrupt {
                    break;
                }
            }
            traces.push(trace);
        }
        traces
    })
    .await
    .expect("CSS-HashCoin timed out");
    let mut reference = None;
    let mut dealer_values = BTreeMap::new();
    let mut rejections = 0;
    for trace in traces {
        let mut frozen = false;
        let mut gathered = false;
        let mut coins = vec![];
        for event in trace {
            match event {
                Event::Gathered { .. } => gathered = true,
                Event::Frozen { .. } => {
                    assert!(gathered);
                    frozen = true;
                }
                Event::TokenReleased { .. } => assert!(frozen),
                Event::Reconstructed {
                    dealer,
                    rejected,
                    value,
                } => {
                    assert!(frozen);
                    if bad.is_some_and(|(d, b)| d == dealer && matches!(b, Behavior::InvalidAx)) {
                        assert!(rejected && value == "0");
                        rejections += 1;
                    } else {
                        assert!(!rejected);
                    }
                    if let Some(prior) = dealer_values.insert(dealer, (rejected, value.clone())) {
                        assert_eq!(prior, (rejected, value));
                    }
                }
                Event::Coin { value, .. } => {
                    assert!(frozen);
                    coins.push(value);
                }
                _ => {}
            }
        }
        assert_eq!(coins.len(), 1);
        if let Some(value) = reference {
            assert_eq!(coins[0], value);
        }
        reference = Some(coins[0]);
    }
    if bad.is_some_and(|(_, b)| matches!(b, Behavior::InvalidAx)) {
        assert!(rejections > 0, "corrupt-sharing path was not exercised");
    }
    for handle in handles {
        handle.shutdown().await.unwrap();
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn four_equal_parties() {
    run(&[1; 4], 1, None, None).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn four_unequal_parties() {
    run(&[3, 2, 4, 3], 4, None, None).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn silent_weight_below_threshold() {
    run(&[3; 4], 4, Some(3), None).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn committed_bad_ax_is_consistently_rejected() {
    run(&[3; 4], 4, None, Some((3, Behavior::InvalidAx))).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn withheld_recovery_does_not_block_honest_output() {
    run(&[3; 4], 4, None, Some((3, Behavior::WithholdRecovery))).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invalid_recovery_tokens_do_not_change_dealer_results() {
    run(&[3; 4], 4, None, Some((3, Behavior::InvalidRecovery))).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn local_file_reuse_keeps_freeze_agreement_silent_liveness_and_ax_rejection() {
    run_with_reuse(&[3; 4], 4, None, None, true).await;
    run_with_reuse(&[1, 2, 4, 5], 4, Some(0), None, true).await;
    run_with_reuse(&[3; 4], 4, None, Some((3, Behavior::InvalidAx)), true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rounded_threshold_boundary_tolerates_maximum_silent_weight() {
    for (weights, t, silent) in [
        ([1u64; 4], 2, 0),
        ([1, 1, 1, 2], 2, 0),
        ([1, 2, 2, 2], 3, 1),
        ([2; 4], 3, 1),
    ] {
        run_with_reuse(&weights, t, Some(silent), None, true).await;
    }
    run_with_reuse(&[1; 4], 2, None, Some((3, Behavior::InvalidAx)), true).await;
}
