use super::*;
use bincode::Options;
use sdc_types::{InstanceId, Weight, WeightedMembership};
fn membership(w: &[u64], t: u64) -> WeightedMembership {
    WeightedMembership::new(
        w.iter().copied().map(Weight::from).collect(),
        Weight::from(t),
    )
    .unwrap()
}
fn instance() -> InstanceId {
    InstanceId::new(7, Some(4), 0)
}
fn msg(kind: Kind) -> Message {
    Message {
        instance: instance(),
        kind,
    }
}
#[test]
fn exact_weight_thresholds_and_self_counting() {
    let mut s = State::new(membership(&[1, 2, 3, 3, 3], 4), 1, instance()).unwrap();
    s.receive(4, msg(Kind::Init([1; 32]))); // Own ECHO contributes weight 2.
    s.receive(2, msg(Kind::Echo([1; 32])));
    s.receive(3, msg(Kind::Echo([1; 32]))); // 8 = W-T: insufficient.
    assert_eq!(s.vote_weights([1; 32])[0].to_string(), "8");
    assert!(
        !s.outgoing
            .iter()
            .any(|a| matches!(a.message.kind, Kind::Ready(_)))
    );
    s.receive(0, msg(Kind::Echo([1; 32]))); // 9 > W-T.
    assert_eq!(s.vote_weights([1; 32])[1].to_string(), "2");
    assert_eq!(
        s.outgoing
            .iter()
            .filter(|a| matches!(a.message.kind, Kind::Ready(_)))
            .count(),
        4
    );
    s.receive(2, msg(Kind::Ready([1; 32])));
    s.receive(3, msg(Kind::Ready([1; 32]))); // 8 = W-T: insufficient.
    assert!(s.delivered.is_none());
    s.receive(0, msg(Kind::Ready([1; 32])));
    assert_eq!(s.delivered, Some([1; 32]));
    assert_eq!(s.events.len(), 1);
    assert!(s.outgoing.iter().all(|a| a.recipient != 1));
    for _ in 0..20 {
        s.receive(1, msg(Kind::Echo([1; 32])));
        s.receive(0, msg(Kind::Ready([2; 32])));
        s.receive(4, msg(Kind::Init([2; 32])));
    }
    assert_eq!(s.vote_weights([1; 32])[0].to_string(), "9");
    assert_eq!(s.events.len(), 1);
    assert_eq!(s.root_count(), 1);
}
#[test]
fn ready_amplifies_at_threshold_without_init_and_late_init_is_still_echoed() {
    let mut s = State::new(membership(&[1, 2, 3, 3, 3], 4), 4, instance()).unwrap();
    s.receive(2, msg(Kind::Ready([9; 32]))); // 3 < T.
    assert!(s.outgoing.is_empty());
    s.receive(0, msg(Kind::Ready([9; 32]))); // 4 = T; own weight 3 makes 7.
    assert_eq!(s.vote_weights([9; 32])[1].to_string(), "7");
    assert_eq!(s.outgoing.len(), 4);
    assert!(s.delivered.is_none());
    s.receive(1, msg(Kind::Ready([9; 32])));
    assert_eq!(s.delivered, Some([9; 32]));
    s.outgoing.clear();
    s.broadcast([9; 32]).unwrap(); // Local Start may happen after peer messages/output.
    assert_eq!(
        s.outgoing
            .iter()
            .filter(|a| matches!(a.message.kind, Kind::Init(_)))
            .count(),
        4
    );
    assert_eq!(
        s.outgoing
            .iter()
            .filter(|a| matches!(a.message.kind, Kind::Echo(_)))
            .count(),
        4
    );
    assert_eq!(s.events.len(), 1);
    assert!(s.broadcast([8; 32]).is_err());
}
#[test]
fn invalid_instances_non_dealer_init_and_floods_cannot_consume_valid_slots_or_grow_state() {
    let mut s: State = State::new(membership(&[1, 2, 3, 3, 3], 4), 1, instance()).unwrap();
    s.receive(0, msg(Kind::Init([7; 32])));
    s.receive(50, msg(Kind::Echo([7; 32])));
    for i in [
        InstanceId::new(8, Some(4), 0),
        InstanceId::new(7, Some(4), 1),
        InstanceId::new(7, Some(3), 0),
    ] {
        s.receive(
            4,
            Message {
                instance: i,
                kind: Kind::Init([7; 32]),
            },
        );
    }
    s.receive(4, msg(Kind::Coded(Box::new(wavid::Kind::Ready([7; 32])))));
    assert!(s.outgoing.is_empty());
    assert_eq!(s.root_count(), 0);
    s.receive(4, msg(Kind::Init([1; 32])));
    for sender in 0..5 {
        for byte in 0..=255u8 {
            s.receive(sender, msg(Kind::Echo([byte; 32])));
            s.receive(sender, msg(Kind::Ready([byte; 32])));
        }
    }
    assert!(s.root_count() <= 10);
    assert!(s.events.len() <= 1);
}
#[test]
fn root_wire_is_exactly_61_bytes_and_malformed_lengths_fail() {
    let codec = || {
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(61)
            .reject_trailing_bytes()
    };
    for kind in [
        Kind::Init([0; 32]),
        Kind::Echo([1; 32]),
        Kind::Ready([2; 32]),
    ] {
        let m = msg(kind);
        let mut raw = codec().serialize(&m).unwrap();
        assert_eq!(raw.len(), 61); // 25 instance + 4 phase + 32 root.
        assert_eq!(codec().deserialize::<Message>(&raw).unwrap(), m);
        assert!(codec().deserialize::<Message>(&raw[..60]).is_err());
        raw.push(0);
        assert!(codec().deserialize::<Message>(&raw).is_err());
    }
}
#[test]
fn wide_weights_and_single_party_need_no_self_network_message() {
    let huge: Weight = format!("0x1{}", "0".repeat(80)).parse().unwrap();
    let m = WeightedMembership::new(vec![huge.clone(); 4], huge).unwrap();
    let i = InstanceId::new(0, Some(0), 0);
    let mut states: Vec<_> = (0..4)
        .map(|id| State::new(m.clone(), id, i).unwrap())
        .collect();
    states[0].broadcast([8; 32]).unwrap();
    drain(&mut states, None, 123);
    assert!(states.iter().all(|s| s.delivered == Some([8; 32])));
    let mut s = State::new(membership(&[3], 1), 0, i).unwrap();
    s.broadcast([6; 32]).unwrap();
    assert_eq!(s.delivered, Some([6; 32]));
    assert!(s.outgoing.is_empty());
}
fn drain(states: &mut [State], silent: Option<usize>, mut seed: u64) {
    let mut queue = vec![];
    let mut steps = 0;
    loop {
        for (id, s) in states.iter_mut().enumerate() {
            if silent == Some(id) {
                continue;
            }
            for a in std::mem::take(&mut s.outgoing) {
                queue.push((id, a.recipient, a.message.clone()));
                queue.push((id, a.recipient, a.message));
            }
        }
        if queue.is_empty() {
            break;
        }
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let (from, to, m) = queue.swap_remove(seed as usize % queue.len());
        if silent != Some(to) {
            states[to].receive(from, m);
        }
        steps += 1;
        assert!(steps < 10000);
    }
}
#[test]
fn adversarial_reordering_silence_and_equivocation_preserve_agreement_and_totality() {
    for seed in [1, 7, 31, 91] {
        let i = InstanceId::new(0, Some(0), 0);
        let mut states: Vec<_> = (0..4)
            .map(|id| State::new(membership(&[3; 4], 4), id, i).unwrap())
            .collect();
        states[0].broadcast([3; 32]).unwrap();
        assert!(states[1].broadcast([3; 32]).is_err());
        drain(&mut states, Some(3), seed);
        assert!(states[..3].iter().all(|s| s.delivered == Some([3; 32])));
    }
    for split in 0..16usize {
        let i = InstanceId::new(0, Some(0), 0);
        let mut states: Vec<_> = (0..4)
            .map(|id| State::new(membership(&[3; 4], 4), id, i).unwrap())
            .collect();
        for id in 1..4 {
            let root = [((split >> id) & 1) as u8; 32];
            for kind in [
                Kind::Init(root),
                Kind::Echo(root),
                Kind::Ready([((split >> (id - 1)) & 1) as u8; 32]),
            ] {
                states[id].receive(0, Message { instance: i, kind });
            }
        }
        drain(&mut states, Some(0), split as u64 + 123);
        if let Some(root) = states[1..].iter().find_map(|s| s.delivered) {
            assert!(states[1..].iter().all(|s| s.delivered == Some(root)));
        }
    }
}
