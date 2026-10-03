use crate::{Context, Event, Parameters, Request};
use std::time::Duration;
use tokio::sync::mpsc;
fn free_base(n: usize) -> u16 {
    for _ in 0..100 {
        let random = crypto::random().unwrap();
        let base = 20000 + u16::from_le_bytes([random[0], random[1]]) % 30000;
        let held = (0..6 * n)
            .map(|i| std::net::TcpListener::bind(("127.0.0.1", base + i as u16)))
            .collect::<std::io::Result<Vec<_>>>();
        if held.is_ok() {
            return base;
        }
    }
    panic!("no local port range available")
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn actual_node_channels_and_six_tcp_services_complete_with_a_silent_peer() {
    complete_with_silent_peer(1).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multibit_channels_complete_with_a_silent_peer() {
    complete_with_silent_peer(128).await;
}
async fn complete_with_silent_peer(output_bits: u32) {
    let configs = super::nodes(&[1; 7], 2, free_base(7));
    let mut handles = vec![];
    let mut inputs = vec![];
    let mut outputs = vec![];
    // Party 6 is silent: B=1 < T=2. These are Rust module tests, not benchmark processes.
    for node in configs.into_iter().take(6) {
        let (input, rx) = mpsc::channel(1);
        let (tx, output) = mpsc::channel(128);
        handles.push(
            Context::spawn(
                node,
                Parameters {
                    coverage_bits: 8,
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
    // Fill the application event channels while the six network services keep working.
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
