use super::*;
use crate::bwavss::Generated;

#[test]
fn service_observer_requires_late_and_zero_coefficient_work_without_mutating_state() {
    let mut s = state(1, 1);
    assert!(!s.service_progress().all_honest_services_complete);
    s.batches[0].started = true;
    s.batches[0].gather = Some((0..4).collect());
    for d in 0..4 {
        let g = material(&s, 0, d);
        deliver(&mut s, 0, d, &g);
        packet(&mut s, 0, d, 0, 0, PRIVATE, &g.packages[0][0]);
        packet(&mut s, 0, d, 0, 1, RECONSTRUCT, &g.packages[1][0]);
        s.batches[0].dealers[d].complete = true;
    }
    freeze(&mut s, 0);
    s.actions.clear();
    assert!(s.complete && s.service_progress().all_honest_services_complete);
    // This coordinate has coefficient zero, but must still serve slower peers.
    s.batches[0].dealers[3].slots[0].sent = false;
    let before = serde_json::to_value(s.service_progress()).unwrap();
    assert!(!s.service_progress().all_honest_services_complete);
    assert_eq!(
        s.service_progress().pending["selected_recovery_services"],
        1
    );
    assert_eq!(before, serde_json::to_value(s.service_progress()).unwrap());
    s.batches[0].dealers[3].slots[0].sent = true;
    s.batches[0].dealers[3].slots[0].private = None;
    assert_eq!(s.service_progress().pending["private_slots"], 1);
    assert!(!s.service_progress().all_honest_services_complete);
}

#[test]
fn common_encoding_and_own_file_reuse_are_bound_into_hashrand_contexts() {
    let s = state(1, 1);
    let base = s.params.context(&s.node, 0, 0);
    for field in ["compact", "reuse"] {
        let mut params = s.params.clone();
        if field == "compact" {
            params.compact_binaa = true;
        } else {
            params.reuse_local_dealer = true;
        }
        params.validate(&s.node).unwrap();
        assert_ne!(base, params.context(&s.node, 0, 0));
        assert_eq!(
            params.layout(&s.node).unwrap().total,
            s.sharing.layout.total
        );
    }
}

fn state(batches: usize, batch_size: usize) -> State {
    let mut node = Node::new();
    node.id = 0;
    node.num_nodes = 4;
    node.session_id = [1; 32];
    node.weights = vec![sdc_types::Weight::from(3); 4];
    node.weight_threshold = Some(sdc_types::Weight::from(4));
    for i in 0..4 {
        node.net_map.insert(i, format!("127.0.0.1:{}", 22000 + i));
        node.sk_map.insert(i, vec![9; 32]);
    }
    State::new(
        &node,
        Parameters {
            batches,
            batch_size,
            ..Parameters::default()
        },
        Behavior::Honest,
    )
    .unwrap()
}
fn material(s: &State, b: usize, d: usize) -> Generated {
    s.sharing
        .generate(
            s.batches[b].dealers[d].context,
            &(0..s.params.slots(b, s.n))
                .map(|slot| s.params.contribution_width(slot))
                .collect::<Vec<_>>(),
            false,
        )
        .unwrap()
}
fn deliver(s: &mut State, b: usize, d: usize, g: &Generated) {
    let bytes = g.roots.concat();
    let instance = s.instance(b, Some(d), 0);
    let codec = wavid::Codec::with_params(
        &s.node.weighted_membership().unwrap(),
        instance,
        s.params.bound_node(&s.node).weighted_public_id("wrbc"),
        bytes.len(),
        wavid::CodingParams { block_bytes: 32 },
    )
    .unwrap();
    s.rbc_event(wrbc::Event::Deliver {
        instance,
        data: codec.commit_file(bytes).unwrap(),
    })
    .unwrap();
}
fn packet(s: &mut State, b: usize, d: usize, slot: usize, owner: usize, kind: u8, bundle: &Bundle) {
    s.packet(
        if kind == PRIVATE { d } else { owner },
        Packet {
            epoch: s.params.epoch + b as u64,
            dealer: d,
            kind,
            payload: bincode::serialize(&SharePacket {
                slot,
                bundle: bundle.clone(),
            })
            .unwrap(),
        },
    )
    .unwrap();
}
fn freeze(s: &mut State, b: usize) {
    s.batches[b].committee = Some((0..4).collect());
    s.binaa_event(wbinaa::Event::DeliverVector {
        instance: s.global(b),
        values: (0..4)
            .map(|d| Dyadic {
                numerator: sdc_types::Weight::from(u64::from(d == 0)),
                exponent: 0,
            })
            .collect(),
    })
    .unwrap();
}

#[test]
fn queued_receipts_wait_for_roots_and_freeze_and_repeated_bad_packets_do_no_work() {
    let mut s = state(1, 1);
    let g = material(&s, 0, 0);
    let mut bad = g.packages[1][0].clone();
    bad.shares[0].value[31] ^= 1;
    packet(&mut s, 0, 0, 0, 0, PRIVATE, &g.packages[0][0]);
    packet(&mut s, 0, 0, 0, 1, RECONSTRUCT, &bad);
    assert_eq!(s.checks, 0);
    deliver(&mut s, 0, 0, &g);
    assert_eq!(s.checks, 2);
    assert!(s.batches[0].dealers[0].echoed);
    assert!(s.batches[0].dealers[0].slots[0].value.is_none());
    assert!(
        !s.actions
            .iter()
            .any(|a| matches!(a, Action::Recovery { .. }))
    );
    for _ in 0..8 {
        packet(&mut s, 0, 0, 0, 1, RECONSTRUCT, &bad);
    }
    assert_eq!(s.checks, 2);
    packet(&mut s, 0, 0, 0, 1, RECONSTRUCT, &g.packages[1][0]);
    assert_eq!(s.checks, 3);
    freeze(&mut s, 0);
    assert!(s.complete);
    assert_eq!(s.checks, 3); // Our already-verified receipt is used without a self packet.
    let steps = s.recovery_steps;
    for _ in 0..8 {
        s.advance().unwrap();
    }
    assert_eq!(s.recovery_steps, steps);
}

#[test]
fn late_private_receipts_and_zero_coefficient_dealers_are_served_after_completion() {
    let mut s = state(1, 1);
    let g = material(&s, 0, 0);
    deliver(&mut s, 0, 0, &g);
    for owner in [1, 2] {
        packet(&mut s, 0, 0, 0, owner, RECONSTRUCT, &g.packages[owner][0]);
    }
    freeze(&mut s, 0);
    assert!(s.complete);
    s.actions.clear();
    packet(&mut s, 0, 0, 0, 0, PRIVATE, &g.packages[0][0]);
    assert_eq!(
        s.actions
            .iter()
            .filter(|a| matches!(a, Action::Recovery { .. }))
            .count(),
        3
    );
    let g1 = material(&s, 0, 1);
    packet(&mut s, 0, 1, 0, 0, PRIVATE, &g1.packages[0][0]);
    s.actions.clear();
    deliver(&mut s, 0, 1, &g1);
    assert_eq!(
        s.actions
            .iter()
            .filter(|a| matches!(a, Action::Recovery { .. }))
            .count(),
        3
    );
    assert_eq!(
        s.events
            .iter()
            .filter(|e| matches!(e, Event::Complete))
            .count(),
        1
    );
}

#[test]
fn reserved_word_release_before_aa_and_out_of_order_batches_keep_all_barriers() {
    let mut s = state(2, 2);
    for b in 0..2 {
        let g = material(&s, b, 0);
        deliver(&mut s, b, 0, &g);
        for slot in 0..s.params.slots(b, 4) {
            for owner in [1, 2] {
                packet(
                    &mut s,
                    b,
                    0,
                    slot,
                    owner,
                    RECONSTRUCT,
                    &g.packages[owner][slot],
                );
            }
        }
    }
    freeze(&mut s, 1); // Later batch AA is ready, but earlier application outputs are not.
    assert_eq!(s.outputs, 0);
    s.ra_event(wra::Event::Output {
        instance: s.instance(1, None, 1),
        value: true,
    })
    .unwrap();
    assert_eq!(s.outputs, 0); // Seed release cannot bypass the source batch's freeze.
    freeze(&mut s, 0);
    assert!(s.complete);
    let outputs: Vec<_> = s
        .events
        .iter()
        .filter_map(|e| match e {
            Event::Beacon { batch, index, .. } => Some((*batch, *index)),
            _ => None,
        })
        .collect();
    assert_eq!(outputs, vec![(0, 0), (0, 1), (1, 0), (1, 1)]);
    assert!(s.batches[1].seed.is_some());
}

#[test]
fn all_private_slots_are_needed_for_sharing_completion_and_seeds_stay_closed() {
    let mut s = state(2, 2);
    let g = material(&s, 0, 0);
    deliver(&mut s, 0, 0, &g);
    packet(&mut s, 0, 0, 0, 0, PRIVATE, &g.packages[0][0]);
    packet(&mut s, 0, 0, 1, 0, PRIVATE, &g.packages[0][1]);
    assert!(!s.batches[0].dealers[0].echoed);
    packet(&mut s, 0, 0, 2, 0, PRIVATE, &g.packages[0][2]);
    assert!(s.batches[0].dealers[0].echoed);
    for slot in 0..3 {
        packet(&mut s, 0, 0, slot, 1, RECONSTRUCT, &g.packages[1][slot]);
    }
    freeze(&mut s, 0);
    assert_eq!(s.outputs, 2);
    assert!(!s.batches[0].open[2]);
    assert!(s.batches[0].output[2].is_none());
    assert!(s.batches[1].seed.is_none());
}
