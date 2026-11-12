use crate::{
    Event, Parameters, State,
    msg::{Action, PRIVATE_TOKEN, RECOVERY_TOKEN, TERMINAL},
};
use network::Packet;
use sdc_types::{Dyadic, Weight};
use wiawvss::{
    Opening, PrivateShare, ax,
    certified::{Certificate, Evidence, Header, Receipt},
};

fn state() -> State {
    State::new(
        &super::nodes(&[1; 7], 2, 20000).remove(0),
        Parameters {
            coverage_bits: 8,
            rounding_bits: 8,
            ..Parameters::default()
        },
    )
    .unwrap()
}
struct Material {
    header: Header,
    file: wavid::ValidatedFile,
    shares: Vec<PrivateShare>,
    receipt: Vec<u8>,
    terminal: Vec<u8>,
}
fn material(s: &State, d: usize) -> Material {
    let mut message = [0; 32];
    message[31] = 7 + d as u8;
    let opening = Opening {
        message,
        randomness: [d as u8 + 9; 32],
    };
    let (public, shares) = ax::generate(&s.setup, &s.dealers[d].context, &opening).unwrap();
    let codec = &s.dealers[d].codec;
    let prepared = codec.prepare(&public.encode()).unwrap();
    let header = Header::new(&s.setup, &s.dealers[d].context, prepared.root);
    let receipt = Receipt::new(&s.setup, codec, &prepared, &shares[s.id])
        .unwrap()
        .encode();
    let terminal = Certificate {
        header_id: header.id(),
        evidence: Evidence::Success(opening),
    }
    .encode();
    let file = codec.commit_file(public.encode()).unwrap();
    Material {
        header,
        file,
        shares,
        receipt,
        terminal,
    }
}
fn rbc(s: &mut State, d: usize, slot: u64, bytes: Vec<u8>) {
    let node = super::nodes(&[1; 7], 2, 20000).remove(0);
    let instance = s.instance(d, slot);
    if slot == 1
        && s.params.list_broadcast == crate::protocol::parameters::ListBroadcast::FixedChunksV1
    {
        s.list_event(crate::root_rbc::chunks::Event {
            instance,
            data: bytes,
        })
        .unwrap();
        return;
    }
    let codec = wavid::Codec::with_params(
        &node.weighted_membership().unwrap(),
        instance,
        s.params
            .bound_node(&node, &s.setup)
            .weighted_public_id("wrbc"),
        bytes.len(),
        Parameters::CONTROL_CODING,
    )
    .unwrap();
    s.rbc_event(wrbc::Event::Deliver {
        instance,
        data: codec.commit_file(bytes).unwrap(),
    })
    .unwrap();
}
fn list(s: &mut State, sender: usize) {
    let selected = (0..s.sampling.quotas[sender]).collect::<Vec<_>>();
    let raw = s.encode_sampling_list(sender, &selected).unwrap();
    rbc(s, sender, 1, raw);
}
fn complete(s: &mut State, d: usize) {
    s.ra_event(wra::Event::Output {
        instance: s.instance(d, 0),
        value: true,
    })
    .unwrap();
}
fn freeze(s: &mut State, positive: usize) {
    // Supply the trusted primitive's local Freeze event; other dealers' values
    // are not prerequisites when their local coefficient is zero.
    s.gather = Some(vec![positive]);
    s.binaa_event(wbinaa::Event::DeliverVector {
        instance: s.global(),
        values: (0..s.n)
            .map(|d| Dyadic {
                numerator: Weight::from(u64::from(d == positive)),
                exponent: 0,
            })
            .collect(),
    })
    .unwrap();
}
fn packet(s: &State, d: usize, kind: u8, payload: Vec<u8>) -> Packet {
    Packet {
        epoch: s.params.epoch,
        dealer: d,
        kind,
        payload,
    }
}
fn permutations() -> Vec<[usize; 4]> {
    let mut orders = vec![];
    for a in 0..4 {
        for b in 0..4 {
            for c in 0..4 {
                for d in 0..4 {
                    if a != b && a != c && a != d && b != c && b != d && c != d {
                        orders.push([a, b, c, d]);
                    }
                }
            }
        }
    }
    assert_eq!(orders.len(), 24);
    orders
}

#[test]
fn duplicate_or_unrelated_events_do_not_visit_dealers_or_aggregate() {
    let mut s = state();
    let m = material(&s, 0);
    let private = packet(&s, 0, PRIVATE_TOKEN, m.receipt.clone());
    s.private_packet(0, private.clone()).unwrap(); // receipt before header
    assert_eq!(s.dealer_visits, [1, 0, 0, 0, 0, 0, 0]);
    for _ in 0..20 {
        s.private_packet(0, private.clone()).unwrap();
        s.binaa_event(wbinaa::Event::DeliverVector {
            instance: s.instance(3, 99),
            values: vec![],
        })
        .unwrap();
    }
    assert_eq!(s.dealer_visits, [1, 0, 0, 0, 0, 0, 0]);
    rbc(&mut s, 0, 0, m.header.encode());
    assert!(s.dealers[0].receipt.is_some());
    s.avid_event(wavid::Event::Stored {
        instance: s.instance(0, 0),
        root: m.header.root,
    })
    .unwrap();
    let visits = s.dealer_visits.clone();
    for _ in 0..20 {
        s.avid_event(wavid::Event::Stored {
            instance: s.instance(0, 0),
            root: m.header.root,
        })
        .unwrap();
    }
    assert_eq!(s.dealer_visits, visits);
    let token = packet(&s, 0, RECOVERY_TOKEN, m.shares[2].encode().to_vec());
    s.recovery_packet(2, token.clone()).unwrap();
    let visits = s.dealer_visits.clone();
    for _ in 0..20 {
        s.recovery_packet(2, token.clone()).unwrap();
    }
    assert_eq!(s.dealer_visits, visits);
    assert!(visits[1..].iter().all(|&n| n == 0));
    assert_eq!(s.aggregation_runs, 0);
    assert_eq!(s.work.len(), 0);
}

#[test]
fn terminal_waiters_resolve_even_when_the_delivered_list_omits_the_dealer_or_is_invalid() {
    for invalid in [false, true] {
        let mut s = state();
        let d = 6;
        let m = material(&s, d);
        rbc(&mut s, d, 0, m.header.encode());
        complete(&mut s, d);
        freeze(&mut s, d);
        let visits = s.dealer_visits.clone();
        s.recovery_packet(1, packet(&s, d, TERMINAL, m.terminal))
            .unwrap();
        assert_eq!(s.dealer_visits, visits); // waits on the list, not unrelated work
        assert!(s.terminal_waiters[1].contains(&d));
        if invalid {
            let bytes = vec![0; s.list_chunk_lengths()[1]];
            rbc(&mut s, 1, 1, bytes);
        } else {
            list(&mut s, 1);
        }
        assert!(s.assignments.delivered(1) && !s.assignments.authorized(1, d));
        assert!(s.dealers[d].pending_terminals.is_empty());
        assert!(s.terminal_waiters[1].is_empty());
        assert!(s.dealers[d].value.is_none());
        assert_eq!(s.remaining, Some(1));
        assert_eq!(s.aggregation_runs, 0);
        let visits = s.dealer_visits.clone();
        list(&mut s, 1); // a final invalid/valid delivery is never replaced
        assert_eq!(s.dealer_visits, visits);
    }
}

#[test]
fn all_orders_of_terminal_authorization_completion_and_freeze_preserve_gating_and_once_only_output()
{
    for order in permutations() {
        let mut s = state();
        let m = material(&s, 0);
        rbc(&mut s, 0, 0, m.header.encode());
        for (position, event) in order.into_iter().enumerate() {
            match event {
                0 => list(&mut s, 1),
                1 => complete(&mut s, 0),
                2 => freeze(&mut s, 0),
                3 => s
                    .recovery_packet(1, packet(&s, 0, TERMINAL, m.terminal.clone()))
                    .unwrap(),
                _ => unreachable!(),
            }
            if position < 3 {
                assert!(s.coin().is_none(), "{order:?}");
            }
        }
        assert!(s.coin().is_some(), "{order:?}");
        assert_eq!(s.remaining, Some(0));
        assert_eq!(s.aggregation_runs, 1);
        assert!(s.dealers[1..].iter().all(|d| d.value.is_none()));
        let events = s.drain_events();
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(e, Event::Terminal { .. }))
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(e, Event::Coin { .. }))
                .count(),
            1
        );
        s.drain_actions();
        list(&mut s, 0); // local authorization arrives after the accepted terminal/output
        let sends = s
            .drain_actions()
            .iter()
            .filter(|a| {
                matches!(a,
            Action::Recovery {packet, ..} if packet.kind == TERMINAL)
            })
            .count();
        assert_eq!(sends, s.n);
        s.recovery_packet(1, packet(&s, 0, TERMINAL, m.terminal.clone()))
            .unwrap();
        list(&mut s, 2);
        s.recovery_packet(2, packet(&s, 0, TERMINAL, m.terminal.clone()))
            .unwrap();
        assert_eq!(s.remaining, Some(0));
        assert_eq!(s.aggregation_runs, 1);
        assert!(
            !s.drain_events()
                .iter()
                .any(|e| matches!(e, Event::Coin { .. } | Event::Terminal { .. }))
        );
    }
}

#[test]
fn all_orders_of_file_tokens_completion_and_freeze_wake_local_recovery() {
    for order in permutations() {
        let mut s = state();
        let m = material(&s, 0);
        rbc(&mut s, 0, 0, m.header.encode());
        list(&mut s, 0); // WAVID only delivers a requested/authorized file.
        for (position, event) in order.into_iter().enumerate() {
            match event {
                0 => s
                    .avid_event(wavid::Event::Result {
                        instance: s.instance(0, 0),
                        result: wavid::Retrieval::File(m.file.clone()),
                    })
                    .unwrap(),
                1 => {
                    for sender in [1, 2] {
                        s.recovery_packet(
                            sender,
                            packet(&s, 0, RECOVERY_TOKEN, m.shares[sender].encode().to_vec()),
                        )
                        .unwrap();
                    }
                }
                2 => complete(&mut s, 0),
                3 => freeze(&mut s, 0),
                _ => unreachable!(),
            }
            if position < 3 {
                assert!(s.coin().is_none(), "{order:?}");
            }
        }
        assert!(s.coin().is_some(), "{order:?}");
        assert_eq!(s.remaining, Some(0));
        assert_eq!(s.aggregation_runs, 1);
    }
}

#[test]
fn zero_coefficient_dealer_completes_and_serves_late_receipts_after_output() {
    let mut s = state();
    let first = material(&s, 0);
    rbc(&mut s, 0, 0, first.header.encode());
    list(&mut s, 1);
    complete(&mut s, 0);
    freeze(&mut s, 0);
    s.recovery_packet(1, packet(&s, 0, TERMINAL, first.terminal))
        .unwrap();
    let coin = s.coin().unwrap();
    s.drain_actions();
    s.drain_events();

    let m = material(&s, 1); // alpha_1 = 0, missing Header/Complete/receipt until now
    rbc(&mut s, 1, 0, m.header.encode());
    complete(&mut s, 1);
    assert!(s.assignments.authorized(1, 1));
    assert!(!s.dealers[1].served[1]);
    s.private_packet(1, packet(&s, 1, PRIVATE_TOKEN, m.receipt.clone()))
        .unwrap();
    let actions = s.drain_actions();
    assert_eq!(actions.iter().filter(|a| matches!(a,
        Action::Recovery {recipient: 1, packet} if packet.kind == RECOVERY_TOKEN && packet.dealer == 1)).count(), 1);
    list(&mut s, 2); // a new service obligation, after both receipt and output
    assert!(s.dealers[1].served[2]);
    s.recovery_packet(1, packet(&s, 1, TERMINAL, m.terminal))
        .unwrap();
    assert!(s.dealers[1].value.is_some());
    assert_eq!(s.remaining, Some(0));
    assert_eq!(s.coin(), Some(coin));
    assert_eq!(s.aggregation_runs, 1);
    assert!(
        s.drain_events()
            .iter()
            .all(|e| !matches!(e, Event::Coin { .. }))
    );
}

fn recovery_messages(actions: Vec<Action>) -> Vec<(usize, usize, u8, Vec<u8>)> {
    actions
        .into_iter()
        .filter_map(|a| match a {
            Action::Recovery { recipient, packet } => Some((
                recipient,
                packet.dealer,
                packet.kind,
                packet.payload.clone(),
            )),
            _ => None,
        })
        .collect()
}

#[test]
fn cooperative_freeze_releases_all_ready_tokens_before_expensive_checks_with_identical_messages() {
    let mut sync = state();
    let mut sliced = state();
    for s in [&mut sync, &mut sliced] {
        list(s, 1);
        for d in 0..2 {
            let m = material(s, d);
            rbc(s, d, 0, m.header.encode());
            complete(s, d);
            s.private_packet(d, packet(s, d, PRIVATE_TOKEN, m.receipt))
                .unwrap();
            s.recovery_packet(1, packet(s, d, TERMINAL, m.terminal))
                .unwrap();
        }
        assert!(s.dealers[..2].iter().all(|d| d.value.is_none()));
        assert!(recovery_messages(s.drain_actions()).is_empty());
        s.drain_events();
    }
    sliced.enable_cooperative_recovery();
    freeze(&mut sync, 0);
    freeze(&mut sliced, 0);
    // No full AX verification has run, yet both token sends are ready to dispatch.
    assert!(sliced.dealers[..2].iter().all(|d| d.value.is_none()));
    assert!(sliced.coin().is_none());
    let mut actual = recovery_messages(sliced.drain_actions());
    assert_eq!(
        actual
            .iter()
            .filter(|(_, _, k, _)| *k == RECOVERY_TOKEN)
            .count(),
        2
    );
    assert!(actual.iter().all(|(_, _, k, _)| *k == RECOVERY_TOKEN));
    assert!(sliced.service_progress().pending["scheduled_recovery"] > 0);
    sliced.resume_recovery().unwrap();
    assert!(sliced.coin().is_some()); // positive d=0 need not wait for zero d=1
    assert!(sliced.dealers[1].value.is_none());
    actual.extend(recovery_messages(sliced.drain_actions()));
    while sliced.recovery_pending() {
        sliced.resume_recovery().unwrap();
        actual.extend(recovery_messages(sliced.drain_actions()));
    }
    assert!(sliced.dealers[1].value.is_some()); // post-output work was retained
    let mut expected = recovery_messages(sync.drain_actions());
    actual.sort();
    expected.sort();
    assert_eq!(actual, expected); // exact packet payloads, recipients and counts
    assert_eq!(sliced.coin(), sync.coin());
    assert_eq!(sliced.aggregation_runs, 1);
    assert_eq!(sliced.service_progress().pending["scheduled_recovery"], 0);
    for s in [&mut sync, &mut sliced] {
        let m = material(s, 1);
        s.private_packet(1, packet(s, 1, PRIVATE_TOKEN, m.receipt))
            .unwrap();
        s.recovery_packet(1, packet(s, 1, TERMINAL, m.terminal))
            .unwrap();
        while s.recovery_pending() {
            s.resume_recovery().unwrap();
        }
        assert!(recovery_messages(s.drain_actions()).is_empty());
    }
}

#[test]
fn cooperative_continuations_preserve_all_orders_of_freeze_completion_and_authorization() {
    for order in permutations() {
        let mut s = state();
        s.enable_cooperative_recovery();
        let m = material(&s, 0);
        rbc(&mut s, 0, 0, m.header.encode());
        while s.recovery_pending() {
            s.resume_recovery().unwrap();
        }
        for (position, event) in order.into_iter().enumerate() {
            match event {
                0 => list(&mut s, 1),
                1 => complete(&mut s, 0),
                2 => freeze(&mut s, 0),
                3 => s
                    .recovery_packet(1, packet(&s, 0, TERMINAL, m.terminal.clone()))
                    .unwrap(),
                _ => unreachable!(),
            }
            // Including resumes before every required gate is present.
            while s.recovery_pending() {
                s.resume_recovery().unwrap();
            }
            assert_eq!(s.coin().is_some(), position == 3, "{order:?}");
        }
        assert_eq!(s.aggregation_runs, 1);
        assert_eq!(s.remaining, Some(0));
    }
}

#[test]
fn cooperative_priority_outputs_before_background_and_still_completes_background() {
    let mut s = state();
    s.enable_cooperative_recovery();
    let background = material(&s, 0);
    let needed = material(&s, 1);
    for (d, m) in [(0, &background), (1, &needed)] {
        rbc(&mut s, d, 0, m.header.encode());
        complete(&mut s, d);
    }
    list(&mut s, 1);
    assert!(s.assignments.authorized(1, 0) && s.assignments.authorized(1, 1));
    freeze(&mut s, 1);
    s.recovery_packet(1, packet(&s, 0, TERMINAL, background.terminal))
        .unwrap();
    s.recovery_packet(1, packet(&s, 1, TERMINAL, needed.terminal))
        .unwrap();
    s.resume_recovery().unwrap();
    assert!(s.coin().is_some());
    assert!(s.dealers[1].value.is_some() && s.dealers[0].value.is_none());
    while s.recovery_pending() {
        s.resume_recovery().unwrap();
    }
    assert!(s.dealers[0].value.is_some());
    assert!(
        s.dealers
            .iter()
            .all(|d| d.tokens.is_empty() && d.recovery_cache.is_none())
    );
}

#[test]
fn one_remote_check_per_continuation_and_honest_terminal_survives_bad_candidates() {
    let mut s = state();
    s.enable_cooperative_recovery();
    let m = material(&s, 1);
    rbc(&mut s, 1, 0, m.header.encode());
    complete(&mut s, 1);
    for sender in [1, 2, 3] {
        list(&mut s, sender);
    }
    list(&mut s, 0);
    freeze(&mut s, 1);
    let bad = Certificate {
        header_id: m.header.id(),
        evidence: Evidence::Success(Opening {
            message: [0; 32],
            randomness: [77; 32],
        }),
    }
    .encode();
    for sender in [1, 2] {
        s.recovery_packet(sender, packet(&s, 1, TERMINAL, bad.clone()))
            .unwrap();
    }
    s.recovery_packet(3, packet(&s, 1, TERMINAL, m.terminal.clone()))
        .unwrap();
    s.drain_events();
    for expected_sender in [1, 2, 3] {
        s.resume_recovery().unwrap();
        let checked = s
            .drain_events()
            .into_iter()
            .filter_map(|e| match e {
                Event::TerminalChecked {
                    sender, accepted, ..
                } => Some((sender, accepted)),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(checked, [(expected_sender, expected_sender == 3)]);
        assert_eq!(s.coin().is_some(), expected_sender == 3);
    }
    assert!(s.dealers[1].pending_terminals.is_empty());
    assert!(s.terminal_waiters.iter().all(|w| !w.contains(&1)));
    // Late recovery data cannot recreate cleared scratch.
    s.recovery_packet(4, packet(&s, 1, TERMINAL, m.terminal))
        .unwrap();
    s.recovery_packet(
        2,
        packet(&s, 1, RECOVERY_TOKEN, m.shares[2].encode().to_vec()),
    )
    .unwrap();
    s.avid_event(wavid::Event::Result {
        instance: s.instance(1, 0),
        result: wavid::Retrieval::File(m.file),
    })
    .unwrap();
    while s.recovery_pending() {
        s.resume_recovery().unwrap();
    }
    assert!(s.dealers[1].tokens.is_empty() && s.dealers[1].recovery_cache.is_none());
}
