use super::*;
use bincode::Options;
use sdc_types::{InstanceId, WeightedMembership};

fn members() -> WeightedMembership {
    WeightedMembership::new(vec![3u64.into(); 4], 4u64.into()).unwrap()
}
fn pump(states: &mut [chunks::Lists], hold_second: bool, held: &mut Vec<(usize, usize, Message)>) {
    let mut queue = vec![];
    let mut seed = 41u64;
    let mut steps = 0;
    loop {
        for (id, s) in states.iter_mut().enumerate().take(3) {
            for a in std::mem::take(&mut s.outgoing) {
                if hold_second && a.message.instance.slot == 2 {
                    held.push((id, a.recipient, a.message));
                } else {
                    queue.push((id, a.recipient, a.message.clone()));
                    queue.push((id, a.recipient, a.message));
                }
            }
        }
        if queue.is_empty() {
            break;
        }
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let (sender, to, msg) = queue.swap_remove(seed as usize % queue.len());
        if to != 3 {
            states[to].receive(sender, msg);
        }
        steps += 1;
        assert!(steps < 10000);
    }
}

#[test]
fn multiple_chunks_wait_for_every_slot_then_deliver_once_despite_silence_and_reordering() {
    let mut states: Vec<_> = (0..4)
        .map(|id| chunks::Lists::new(members(), id, 7, &[128; 4]).unwrap())
        .collect();
    let instance = InstanceId::new(7, Some(0), 1);
    let data: Vec<_> = (0..128).collect();
    assert!(states[1].broadcast(instance, &data).is_err());
    assert!(states[0].broadcast(instance, &data[..64]).is_err());
    states[0].broadcast(instance, &data).unwrap();
    assert!(states[0].broadcast(instance, &data).is_err());
    let mut held = vec![];
    pump(&mut states, true, &mut held);
    assert!(!held.is_empty());
    assert!(
        states.iter().all(|s| s.events.is_empty()),
        "one block must not publish a list"
    );
    for (sender, to, msg) in held.drain(..).rev() {
        if to != 3 {
            states[to].receive(sender, msg);
        }
    }
    pump(&mut states, false, &mut held);
    for state in &states[..3] {
        assert_eq!(state.events.len(), 1);
        assert_eq!(state.events[0].instance, instance);
        assert_eq!(state.events[0].data, data);
        assert_eq!(state.instance_count(), 8);
    }
    for slot in [0, 3, 99, u64::MAX] {
        for state in &mut states[..3] {
            for kind in [
                Kind::ChunkInit([[7; 32]; 2]),
                Kind::ChunkEcho([[7; 32]; 2]),
                Kind::ChunkReady([[7; 32]; 2]),
            ] {
                state.receive(
                    0,
                    Message {
                        instance: InstanceId::new(7, Some(0), slot),
                        kind,
                    },
                );
            }
        }
    }
    assert!(
        states[..3]
            .iter()
            .all(|s| s.events.len() == 1 && s.instance_count() == 8)
    );
}

#[test]
fn chunk_phases_are_exactly_93_bytes_and_do_not_accept_root_or_coded_votes() {
    let instance = InstanceId::new(7, Some(0), 1);
    let block = [[7; 32], [19; 32]];
    let codec = || {
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(93)
            .reject_trailing_bytes()
    };
    for kind in [
        Kind::ChunkInit(block),
        Kind::ChunkEcho(block),
        Kind::ChunkReady(block),
    ] {
        let msg = Message { instance, kind };
        let mut raw = codec().serialize(&msg).unwrap();
        assert_eq!(raw.len(), 93); // 25-byte instance, 4-byte phase, fixed 64 B payload.
        assert_eq!(codec().deserialize::<Message>(&raw).unwrap(), msg);
        assert!(codec().deserialize::<Message>(&raw[..92]).is_err());
        raw.push(0);
        assert!(codec().deserialize::<Message>(&raw).is_err());
    }
    let mut state = State::<recovery::ranked::Block>::new(members(), 1, instance).unwrap();
    for kind in [
        Kind::Init([7; 32]),
        Kind::Echo([7; 32]),
        Kind::Ready([7; 32]),
        Kind::Coded(Box::new(wavid::Kind::Ready([7; 32]))),
    ] {
        state.receive(0, Message { instance, kind });
    }
    assert_eq!(state.root_count(), 0);
    for sender in [0, 2] {
        state.receive(
            sender,
            Message {
                instance,
                kind: Kind::ChunkReady(block),
            },
        );
    }
    assert_eq!(state.delivered, Some(block)); // w=9>W-T, without INIT.
    state.receive(
        0,
        Message {
            instance,
            kind: Kind::ChunkInit(block),
        },
    );
    assert!(
        state
            .outgoing
            .iter()
            .any(|a| matches!(a.message.kind, Kind::ChunkEcho(_)))
    );
    assert_eq!(state.events.len(), 1);
}

#[test]
fn equivocation_and_replays_preserve_chunk_agreement_and_totality() {
    for split in 0..16usize {
        let mut states: Vec<_> = (0..4)
            .map(|id| chunks::Lists::new(members(), id, 7, &[64; 4]).unwrap())
            .collect();
        // Corrupt dealer 3: arbitrary inconsistent phase values. Silent in pump.
        let instance = InstanceId::new(7, Some(3), 1);
        for (id, state) in states.iter_mut().enumerate().take(3) {
            let block = [[(split >> id & 1) as u8; 32]; 2];
            for kind in [
                Kind::ChunkInit(block),
                Kind::ChunkEcho(block),
                Kind::ChunkReady(block),
            ] {
                state.receive(3, Message { instance, kind });
            }
        }
        pump(&mut states, false, &mut vec![]);
        if let Some(value) = states[..3]
            .iter()
            .find_map(|s| s.events.first().map(|e| e.data.clone()))
        {
            assert!(
                states[..3]
                    .iter()
                    .all(|s| s.events.len() == 1 && s.events[0].data == value)
            );
        }
    }
}

#[test]
fn instance_budget_is_checked_before_allocating_chunk_votes() {
    assert!(chunks::Lists::new(members(), 0, 7, &[65; 4]).is_err());
    assert!(chunks::Lists::new(members(), 0, 7, &[64]).is_err());
    assert!(chunks::Lists::new(members(), 0, 7, &[64 * 1024; 4]).is_err());
}

#[test]
fn normal_path_list_ledgers_match_complete_four_party_message_traces() {
    let instance = InstanceId::new(7, Some(0), 1);
    let mut coded: Vec<_> = (0..4)
        .map(|id| wrbc::State::new(members(), id, instance, [7; 32], 48).unwrap())
        .collect();
    coded[0].broadcast(&[0; 48]).unwrap();
    let mut bytes = 0usize;
    let mut queue = std::collections::VecDeque::new();
    loop {
        for (id, s) in coded.iter_mut().enumerate() {
            for a in std::mem::take(&mut s.outgoing) {
                if id != a.recipient {
                    bytes += bincode::serialized_size(&Message {
                        instance: a.message.instance,
                        kind: Kind::Coded(Box::new(a.message.kind.clone())),
                    })
                    .unwrap() as usize
                        + 132;
                }
                queue.push_back((id, a.recipient, a.message));
            }
        }
        let Some((sender, to, msg)) = queue.pop_front() else {
            break;
        };
        coded[to].receive(sender, msg);
    }
    assert!(coded.iter().all(|s| s.delivered.is_some()));
    let codec = wavid::Codec::new(&members(), instance, [7; 32], 48).unwrap();
    let bulk: usize = (0..4)
        .map(|owner| {
            let raw = codec.bundle_bytes(owner);
            (4 - usize::from(owner == 0)) * (raw + 177 * raw.div_ceil(wavid::CHUNK_BYTES))
        })
        .sum();
    assert_eq!(bytes, bulk + 3 * 4 * 3 * 197);
    let mut short: Vec<_> = (0..4)
        .map(|id| chunks::Lists::new(members(), id, 7, &[64; 4]).unwrap())
        .collect();
    short[0].broadcast(instance, &[0; 64]).unwrap();
    let mut queue = std::collections::VecDeque::new();
    let mut bytes = 0usize;
    loop {
        for (id, s) in short.iter_mut().enumerate() {
            for a in std::mem::take(&mut s.outgoing) {
                bytes += bincode::serialized_size(&a.message).unwrap() as usize + 132;
                queue.push_back((id, a.recipient, a.message));
            }
        }
        let Some((sender, to, msg)) = queue.pop_front() else {
            break;
        };
        short[to].receive(sender, msg);
    }
    assert!(short.iter().all(|s| s.events.len() == 1));
    assert_eq!(bytes, 225 * 3 * (2 * 4 + 1));
}
