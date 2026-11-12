use super::*;
use crate::{
    Behavior, Parameters,
    msg::{Action, Event, PRIVATE, RECONSTRUCT},
};
use network::Packet;
use sdc_types::Dyadic;
use wiawvss::{Opening, PrivateShare, compact};

#[test]
fn compact_binaa_is_validated_and_session_bound_without_changing_css() {
    let n = node();
    let plain = Parameters::default();
    let compact = Parameters {
        compact_binaa: true,
        ..plain.clone()
    };
    compact.validate(&n).unwrap();
    assert_ne!(
        plain.bound_node(&n).session_id,
        compact.bound_node(&n).session_id
    );
    assert_eq!(
        plain.setup(&n).unwrap().id(),
        compact.setup(&n).unwrap().id()
    );
}

fn node() -> config::Node {
    let mut n = config::Node::new();
    n.id = 0;
    n.num_nodes = 4;
    n.session_id = [1; 32];
    n.weights = vec![sdc_types::Weight::from(3); 4];
    n.weight_threshold = Some(sdc_types::Weight::from(4));
    for i in 0..4 {
        n.net_map.insert(i, format!("127.0.0.1:{}", 22000 + i));
        n.sk_map.insert(i, vec![9; 32]);
    }
    n
}
fn state() -> State {
    State::new(&node(), Parameters::default(), Behavior::Honest).unwrap()
}

#[test]
fn reused_own_rbc_file_still_requires_freeze_and_threshold_private_tokens() {
    for freeze_first in [false, true] {
        let n = node();
        let mut s = State::new(
            &n,
            Parameters {
                reuse_local_dealer: true,
                ..Parameters::default()
            },
            Behavior::Honest,
        )
        .unwrap();
        s.start().unwrap();
        let actions = s.drain_actions();
        let data = actions
            .iter()
            .find_map(|a| match a {
                Action::Rbc(wrbc::Request::Broadcast { data, .. }) => Some(data.clone()),
                _ => None,
            })
            .unwrap();
        let shares = actions
            .iter()
            .filter_map(|a| match a {
                Action::Private { packet, .. } => {
                    Some(PrivateShare::decode(&packet.payload).unwrap())
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        let mut rbc = wrbc::State::with_params_and_local_reuse(
            n.weighted_membership().unwrap(),
            0,
            s.instance(0),
            s.params.bound_node(&n).weighted_public_id("wrbc"),
            data.len(),
            s.params.coding(),
            true,
        )
        .unwrap();
        rbc.broadcast(&data).unwrap();
        let root = rbc.storage.codec.commit_file(data).unwrap().root();
        assert!(rbc.delivered.is_none() && s.dealers[0].public.is_none());
        for sender in 1..4 {
            rbc.receive(
                sender,
                wrbc::ProtMsg {
                    instance: s.instance(0),
                    kind: wavid::Kind::Ready(root),
                },
            );
        }
        assert!(rbc.delivered.is_some() && rbc.storage.result.is_none());
        for e in rbc.events {
            s.rbc_event(e).unwrap();
        }
        s.packet(0, packet(PRIVATE, &shares[0])).unwrap();
        assert!(s.dealers[0].value.is_none());
        assert!(
            !s.drain_actions()
                .iter()
                .any(|a| matches!(a, Action::Recovery { .. }))
        );
        if freeze_first {
            freeze(&mut s);
        }
        assert!(s.dealers[0].value.is_none());
        s.packet(0, packet(RECONSTRUCT, &shares[0])).unwrap();
        assert!(s.dealers[0].value.is_none()); // Own weight 3 is below T=4.
        s.packet(1, packet(RECONSTRUCT, &shares[1])).unwrap();
        if !freeze_first {
            assert!(s.dealers[0].value.is_none());
            freeze(&mut s);
        }
        assert!(s.coin().is_some());
        assert_eq!(s.dealers[0].recovery_attempts, 1);
        let events = s.drain_events();
        let freeze = events
            .iter()
            .position(|e| matches!(e, Event::Frozen { .. }))
            .unwrap();
        let recovered = events
            .iter()
            .position(|e| matches!(e, Event::Reconstructed { dealer: 0, .. }))
            .unwrap();
        assert!(freeze < recovered);
    }
}
fn packet(kind: u8, share: &PrivateShare) -> Packet {
    Packet {
        epoch: 0,
        dealer: 0,
        kind,
        payload: share.encode().to_vec(),
    }
}
fn material(s: &State) -> (compact::Public, Vec<PrivateShare>) {
    let mut message = [0; 32];
    message[31] = 7;
    compact::generate(
        &s.setup,
        &s.dealers[0].context,
        &Opening {
            message,
            randomness: [9; 32],
        },
    )
    .unwrap()
}
fn deliver(s: &mut State, bytes: &[u8]) {
    let node = node();
    let codec = wavid::Codec::with_params(
        &node.weighted_membership().unwrap(),
        s.instance(0),
        s.params.bound_node(&node).weighted_public_id("wrbc"),
        bytes.len(),
        s.params.coding(),
    )
    .unwrap();
    s.deliver_public(0, codec.commit_file(bytes.to_vec()).unwrap());
}
fn freeze(s: &mut State) {
    s.gather = Some(vec![0]);
    s.binaa_event(wbinaa::Event::DeliverVector {
        instance: s.global(),
        values: (0..4)
            .map(|i| Dyadic {
                numerator: sdc_types::Weight::from(u64::from(i == 0)),
                exponent: 0,
            })
            .collect(),
    })
    .unwrap();
}
#[test]
fn full_public_and_valid_private_input_are_both_required_for_ra() {
    let mut s = state();
    let (public, shares) = material(&s);
    s.packet(0, packet(PRIVATE, &shares[0])).unwrap();
    assert!(s.drain_actions().is_empty());
    deliver(&mut s, &public.encode());
    s.advance().unwrap();
    assert_eq!(
        s.drain_actions()
            .iter()
            .filter(|a| matches!(a, Action::Ra(wra::Request::Input { value: true, .. })))
            .count(),
        1
    );
    assert!(!s.is_frozen());
    assert!(
        !s.drain_events()
            .iter()
            .any(|e| matches!(e, Event::TokenReleased { .. }))
    );
}
#[test]
fn token_release_waits_for_freeze_and_delayed_receipt_is_served_after_output() {
    let mut s = state();
    let (public, shares) = material(&s);
    deliver(&mut s, &public.encode());
    s.advance().unwrap();
    assert!(
        !s.drain_actions()
            .iter()
            .any(|a| matches!(a, Action::Ra(wra::Request::Input { .. })))
    );
    s.packet(1, packet(RECONSTRUCT, &shares[1])).unwrap();
    s.packet(2, packet(RECONSTRUCT, &shares[2])).unwrap();
    assert!(s.dealers[0].value.is_none());
    freeze(&mut s);
    assert!(s.coin().is_some()); // No local private receipt was needed to recover.
    assert!(!s.dealers[0].served);
    s.drain_actions();
    s.drain_events();
    s.packet(0, packet(PRIVATE, &shares[0])).unwrap();
    assert_eq!(
        s.drain_actions()
            .iter()
            .filter(|a| matches!(a, Action::Recovery { .. }))
            .count(),
        4
    );
    assert!(
        s.drain_events()
            .iter()
            .any(|e| matches!(e, Event::TokenReleased { dealer: 0 }))
    );
    s.packet(0, packet(PRIVATE, &shares[0])).unwrap();
    assert!(s.drain_actions().is_empty());
}
#[test]
fn ra_completion_does_not_require_the_local_private_share() {
    let mut s = state();
    let (public, _) = material(&s);
    deliver(&mut s, &public.encode());
    s.advance().unwrap();
    s.drain_actions();
    s.ra_event(wra::Event::Output {
        instance: s.instance(0),
        value: true,
    })
    .unwrap();
    assert!(s.dealers[0].receipt.is_none());
    assert!(
        s.drain_actions()
            .iter()
            .any(|a| matches!(a, Action::Gather(wgather::Request::Add { dealer: 0, .. })))
    );
}
#[test]
fn invalid_duplicate_or_replayed_tokens_do_not_become_rejection() {
    let mut s = state();
    let (public, shares) = material(&s);
    deliver(&mut s, &public.encode());
    s.advance().unwrap();
    freeze(&mut s);
    s.packet(0, packet(RECONSTRUCT, &shares[0])).unwrap();
    s.packet(0, packet(RECONSTRUCT, &shares[0])).unwrap();
    s.packet(1, packet(RECONSTRUCT, &shares[0])).unwrap(); // wrong authenticated sender
    let mut bad = shares[1].clone();
    bad.token[0] ^= 1;
    s.packet(1, packet(RECONSTRUCT, &bad)).unwrap();
    let mut stale = packet(RECONSTRUCT, &shares[1]);
    stale.epoch = 1;
    s.packet(1, stale).unwrap();
    assert!(s.coin().is_none() && s.dealers[0].value.is_none());
    s.packet(1, packet(RECONSTRUCT, &shares[1])).unwrap();
    assert_eq!(s.dealers[0].value.as_ref().unwrap().to_string(), "7");
    assert!(s.coin().is_some());
}
#[test]
fn malformed_public_or_a_private_share_alone_cannot_start_completion() {
    let mut s = state();
    let (public, shares) = material(&s);
    let mut bytes = public.encode();
    bytes[0] ^= 1;
    deliver(&mut s, &bytes);
    s.packet(0, packet(PRIVATE, &shares[0])).unwrap();
    assert!(s.drain_actions().is_empty());
    assert!(!s.dealers[0].echoed);
}
#[test]
fn out_of_range_valid_ax_message_maps_to_zero_after_reconstruction() {
    let mut s = state();
    let opening = Opening {
        message: {
            let mut m = [0; 32];
            m[1] = 1;
            m
        },
        randomness: [8; 32],
    };
    let (public, shares) = compact::generate(&s.setup, &s.dealers[0].context, &opening).unwrap();
    deliver(&mut s, &public.encode());
    s.advance().unwrap();
    freeze(&mut s);
    for (sender, share) in shares.iter().enumerate().take(2) {
        s.packet(sender, packet(RECONSTRUCT, share)).unwrap();
    }
    assert!(
        s.drain_events()
            .iter()
            .any(|e| matches!(e, Event::Reconstructed { rejected: true, .. }))
    );
}
#[test]
fn configuration_has_no_batch_or_sampling_option_and_binds_all_coin_parameters() {
    assert!(serde_json::from_str::<Parameters>(r#"{"batch_size":2}"#).is_err());
    assert!(serde_json::from_str::<Parameters>(r#"{"coverage_bits":40}"#).is_err());
    let p = Parameters::default();
    let mut other = p.clone();
    other.rounding_bits += 1;
    assert_ne!(
        p.bound_node(&node()).session_id,
        other.bound_node(&node()).session_id
    );
}

#[test]
fn repeated_invalid_tokens_are_cached_and_unrelated_events_do_not_scan_dealers() {
    let mut s = state();
    let (public, shares) = material(&s);
    deliver(&mut s, &public.encode());
    s.advance().unwrap();
    freeze(&mut s);
    let steps = s.dealer_steps;
    for _ in 0..12 {
        s.advance().unwrap();
    }
    assert_eq!(s.dealer_steps, steps);
    let mut bad = shares[1].clone();
    bad.token[0] ^= 1;
    for _ in 0..12 {
        s.packet(1, packet(RECONSTRUCT, &bad)).unwrap();
    }
    assert_eq!(s.dealers[0].token_checks, 1);
    assert_eq!(s.dealer_steps - steps, 1); // repeats do not even reschedule the dealer
    assert_eq!(s.dealers[0].recovery_attempts, 0);
    assert!(s.dealers[0].verified_weight.is_zero());
    s.packet(0, packet(RECONSTRUCT, &shares[0])).unwrap();
    assert_eq!(s.dealers[0].recovery_attempts, 0);
    s.packet(1, packet(RECONSTRUCT, &shares[1])).unwrap();
    assert_eq!(s.dealers[0].recovery_attempts, 1);
    assert_eq!(s.dealers[0].value.as_ref().unwrap().to_string(), "7");
    for share in &shares {
        s.packet(share.party, packet(RECONSTRUCT, share)).unwrap();
    }
    assert_eq!(s.dealers[0].recovery_attempts, 1);
    assert_eq!(s.remaining, 0);
}

#[test]
fn queued_tokens_are_activated_when_public_record_arrives_after_freeze() {
    let mut s = state();
    let (public, shares) = material(&s);
    s.packet(0, packet(PRIVATE, &shares[0])).unwrap();
    s.packet(1, packet(RECONSTRUCT, &shares[1])).unwrap();
    s.packet(2, packet(RECONSTRUCT, &shares[2])).unwrap();
    freeze(&mut s);
    assert!(s.coin().is_none());
    assert_eq!(s.remaining, 1);
    deliver(&mut s, &public.encode());
    s.advance().unwrap();
    assert!(s.coin().is_some());
    assert_eq!(s.remaining, 0);
    assert_eq!(s.dealers[0].recovery_attempts, 1);
    assert!(s.dealers[0].served && s.dealers[0].echoed);
}

#[test]
fn zero_coefficient_dealer_still_recovers_and_serves_late_receipts_after_output() {
    for cooperative in [false, true] {
        zero_coefficient_service_case(cooperative);
    }
}
fn zero_coefficient_service_case(cooperative: bool) {
    let mut s = state();
    if cooperative {
        s.enable_cooperative_recovery();
    }
    let (public, shares) = material(&s);
    deliver(&mut s, &public.encode());
    s.advance().unwrap();
    freeze(&mut s);
    s.packet(1, packet(RECONSTRUCT, &shares[1])).unwrap();
    s.packet(2, packet(RECONSTRUCT, &shares[2])).unwrap();
    finish_scheduled(&mut s);
    let coin = s.coin().unwrap();
    s.drain_actions();
    s.drain_events();
    let d = 1;
    let (late, private) = compact::generate(
        &s.setup,
        &s.dealers[d].context,
        &Opening {
            message: [0; 32],
            randomness: [87; 32],
        },
    )
    .unwrap();
    let node = node();
    let codec = wavid::Codec::with_params(
        &node.weighted_membership().unwrap(),
        s.instance(d),
        s.params.bound_node(&node).weighted_public_id("wrbc"),
        late.byte_len(),
        s.params.coding(),
    )
    .unwrap();
    s.rbc_event(wrbc::Event::Deliver {
        instance: s.instance(d),
        data: codec.commit_file(late.encode()).unwrap(),
    })
    .unwrap();
    for i in [1, 2] {
        let mut p = packet(RECONSTRUCT, &private[i]);
        p.dealer = d;
        s.packet(i, p).unwrap();
    }
    finish_scheduled(&mut s);
    assert!(s.dealers[d].value.is_some());
    assert_eq!(s.remaining, 0);
    let mut p = packet(PRIVATE, &private[0]);
    p.dealer = d;
    s.packet(d, p).unwrap();
    assert_eq!(
        s.drain_actions()
            .iter()
            .filter(|a| matches!(a, Action::Recovery { packet, .. } if packet.dealer == d))
            .count(),
        4
    );
    assert!(
        s.drain_events()
            .iter()
            .all(|e| !matches!(e, Event::Coin { .. } | Event::Complete))
    );
    assert_eq!(s.coin(), Some(coin));
}

fn finish_scheduled(s: &mut State) {
    let mut steps = 0;
    while s.recovery_pending() {
        s.resume_recovery().unwrap();
        steps += 1;
        assert!(
            steps <= s.n,
            "each dealer has at most one queued continuation"
        );
    }
}

#[test]
fn cooperative_recovery_preserves_gate_orders_and_recovery_bytes() {
    // Public file, private receipt, threshold recovery tokens and Freeze can
    // arrive in any order. Exercise both eager and delayed continuations.
    for a in 0..4 {
        for b in 0..4 {
            for c in 0..4 {
                for d in 0..4 {
                    let order = [a, b, c, d];
                    if order
                        .iter()
                        .copied()
                        .collect::<std::collections::BTreeSet<_>>()
                        .len()
                        != 4
                    {
                        continue;
                    }
                    for eager in [false, true] {
                        let mut sync = state();
                        let mut queued = state();
                        queued.enable_cooperative_recovery();
                        let (public, shares) = material(&sync);
                        let bytes = public.encode();
                        let mut seen = [false; 4];
                        for op in order {
                            seen[op] = true;
                            for s in [&mut sync, &mut queued] {
                                match op {
                                    0 => {
                                        deliver(s, &bytes);
                                        s.advance().unwrap();
                                    }
                                    1 => s.packet(0, packet(PRIVATE, &shares[0])).unwrap(),
                                    2 => {
                                        s.packet(1, packet(RECONSTRUCT, &shares[1])).unwrap();
                                        s.packet(2, packet(RECONSTRUCT, &shares[2])).unwrap();
                                    }
                                    3 => freeze(s),
                                    _ => unreachable!(),
                                }
                                if !seen[3] {
                                    assert!(!s.dealers[0].served && s.dealers[0].value.is_none());
                                }
                                if !(seen[0] && seen[2] && seen[3]) {
                                    assert!(s.coin().is_none());
                                }
                            }
                            if eager {
                                finish_scheduled(&mut queued);
                            }
                        }
                        if !eager {
                            assert!(queued.dealers[0].served);
                            assert_eq!(queued.dealers[0].recovery_attempts, 0);
                            assert!(queued.coin().is_none());
                        }
                        finish_scheduled(&mut queued);
                        assert_eq!(sync.coin(), queued.coin());
                        assert!(queued.coin().is_some());
                        assert_eq!(queued.remaining, 0);
                        assert_eq!(queued.dealers[0].recovery_attempts, 1);
                        let recovery_bytes = |s: &mut State| {
                            let mut out = s
                                .drain_actions()
                                .into_iter()
                                .filter_map(|action| {
                                    if let Action::Recovery { recipient, packet } = action {
                                        Some((
                                            recipient,
                                            packet.epoch,
                                            packet.dealer,
                                            packet.kind,
                                            packet.payload.clone(),
                                        ))
                                    } else {
                                        None
                                    }
                                })
                                .collect::<Vec<_>>();
                            out.sort();
                            out
                        };
                        let expected = recovery_bytes(&mut sync);
                        assert_eq!(expected.len(), 4);
                        assert_eq!(expected, recovery_bytes(&mut queued));
                        let events = queued.drain_events();
                        assert_eq!(
                            events
                                .iter()
                                .filter(|e| matches!(e, Event::Coin { .. }))
                                .count(),
                            1
                        );
                        for share in &shares {
                            queued
                                .packet(share.party, packet(RECONSTRUCT, share))
                                .unwrap();
                        }
                        finish_scheduled(&mut queued);
                        assert_eq!(queued.dealers[0].recovery_attempts, 1);
                        assert!(recovery_bytes(&mut queued).is_empty());
                        assert!(queued.drain_events().is_empty());
                    }
                }
            }
        }
    }
}

#[test]
fn cooperative_recovery_retains_authorization_after_invalid_tokens() {
    let mut s = state();
    s.enable_cooperative_recovery();
    let (public, shares) = material(&s);
    deliver(&mut s, &public.encode());
    s.advance().unwrap();
    freeze(&mut s);
    s.packet(0, packet(RECONSTRUCT, &shares[0])).unwrap();
    let mut bad = shares[1].clone();
    bad.token[0] ^= 1;
    s.packet(1, packet(RECONSTRUCT, &bad)).unwrap();
    s.packet(1, packet(RECONSTRUCT, &shares[0])).unwrap();
    let mut replay = packet(RECONSTRUCT, &shares[1]);
    replay.epoch += 1;
    s.packet(1, replay).unwrap();
    finish_scheduled(&mut s);
    assert!(s.coin().is_none());
    assert_eq!(s.dealers[0].recovery_attempts, 0);
    s.packet(1, packet(RECONSTRUCT, &shares[1])).unwrap();
    finish_scheduled(&mut s);
    assert!(s.coin().is_some());
    assert_eq!(s.dealers[0].recovery_attempts, 1);
    assert!(!s.dealers[0].served);
    s.drain_actions();
    // A receipt arriving after output must still be sent to all peers.
    s.packet(0, packet(PRIVATE, &shares[0])).unwrap();
    finish_scheduled(&mut s);
    assert_eq!(
        s.drain_actions()
            .iter()
            .filter(|a| matches!(a, Action::Recovery { .. }))
            .count(),
        4
    );
    s.packet(0, packet(PRIVATE, &shares[0])).unwrap();
    finish_scheduled(&mut s);
    assert!(s.drain_actions().is_empty());
}

#[test]
fn cooperative_priority_preserves_zero_coefficient_recovery_after_output() {
    let mut s = state();
    s.enable_cooperative_recovery();
    let n = node();
    let mut materials = vec![];
    for d in 0..2 {
        let (public, shares) = compact::generate(
            &s.setup,
            &s.dealers[d].context,
            &Opening {
                message: [0; 32],
                randomness: [41 + d as u8; 32],
            },
        )
        .unwrap();
        let codec = wavid::Codec::with_params(
            &n.weighted_membership().unwrap(),
            s.instance(d),
            s.params.bound_node(&n).weighted_public_id("wrbc"),
            public.byte_len(),
            s.params.coding(),
        )
        .unwrap();
        s.rbc_event(wrbc::Event::Deliver {
            instance: s.instance(d),
            data: codec.commit_file(public.encode()).unwrap(),
        })
        .unwrap();
        materials.push(shares);
    }
    freeze(&mut s);
    // Background work becomes ready first; no local timing assumptions.
    for d in [1, 0] {
        for sender in [1, 2] {
            let mut p = packet(RECONSTRUCT, &materials[d][sender]);
            p.dealer = d;
            s.packet(sender, p).unwrap();
        }
    }
    s.resume_recovery().unwrap();
    assert!(s.coin().is_some() && s.dealers[1].value.is_none());
    assert!(s.dealers[0].tokens.is_empty() && s.dealers[0].checked_tokens.is_empty());
    finish_scheduled(&mut s);
    assert!(s.dealers[1].value.is_some() && s.dealers[1].tokens.is_empty());
    for (d, shares) in materials.iter().enumerate() {
        let mut p = packet(PRIVATE, &shares[0]);
        p.dealer = d;
        s.packet(d, p).unwrap();
    }
    assert_eq!(
        s.drain_actions()
            .iter()
            .filter(|a| matches!(a, Action::Recovery { .. }))
            .count(),
        8
    );
}
