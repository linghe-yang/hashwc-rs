use std::collections::VecDeque;
use types::{InstanceId, Weight, WeightedMembership};
use wrbc::{Event, State};

fn nodes(reuse: bool, bytes: usize) -> Vec<State> {
    let membership = WeightedMembership::new(vec![Weight::from(3); 4], Weight::from(4)).unwrap();
    (0..4)
        .map(|id| {
            State::with_params_and_local_reuse(
                membership.clone(),
                id,
                InstanceId::new(7, Some(0), 0),
                [9; 32],
                bytes,
                Default::default(),
                reuse,
            )
            .unwrap()
        })
        .collect()
}
fn ready(s: &mut State, root: [u8; 32], senders: &[usize]) {
    for &sender in senders {
        s.receive(
            sender,
            wrbc::ProtMsg {
                instance: s.storage.instance,
                kind: wavid::Kind::Ready(root),
            },
        );
    }
}

#[test]
fn canonical_file_waits_for_quorum_and_never_requests_own_data() {
    let mut s = nodes(true, 139).remove(0);
    let data = vec![31; 139];
    s.broadcast(&data).unwrap();
    let root = s.storage.codec.commit_file(data.clone()).unwrap().root();
    assert!(s.delivered.is_none());
    ready(&mut s, root, &[1, 2]); // Weight 6 < required >8.
    assert!(s.delivered.is_none());
    ready(&mut s, root, &[3]);
    assert_eq!(s.delivered.as_deref(), Some(data.as_slice()));
    assert!(s.storage.result.is_none()); // No distributed decoding occurred.
    assert!(
        !s.outgoing
            .iter()
            .any(|a| matches!(a.message.kind, wavid::Kind::Request(_)))
    );
    assert_eq!(
        s.events
            .iter()
            .filter(|e| matches!(e, Event::Deliver { .. }))
            .count(),
        1
    );
    ready(&mut s, root, &[1, 2, 3]);
    assert_eq!(
        s.events
            .iter()
            .filter(|e| matches!(e, Event::Deliver { .. }))
            .count(),
        1
    );
    assert!(s.broadcast(&data).is_err());
}

#[test]
fn early_quorum_wrong_root_and_failed_broadcast_cannot_seed_local_delivery() {
    for mismatch in [false, true] {
        let mut s = nodes(true, 139).remove(0);
        let data = vec![31; 139];
        let mut root = s.storage.codec.commit_file(data.clone()).unwrap().root();
        if mismatch {
            root[0] ^= 1;
        }
        // Exercise completion-before-local-start explicitly, even though an
        // honest origin's packets normally precede the receivers' READY votes.
        ready(&mut s, root, &[1, 2, 3]);
        assert!(s.delivered.is_none());
        assert!(
            !s.outgoing
                .iter()
                .any(|a| matches!(a.message.kind, wavid::Kind::Request(_)))
        );
        assert!(s.broadcast(&[0; 138]).is_err());
        assert!(s.delivered.is_none());
        s.broadcast(&data).unwrap();
        assert_eq!(s.delivered.is_some(), !mismatch);
    }
    let mut remote = nodes(true, 139).remove(1);
    assert!(remote.broadcast(&[0; 139]).is_err());
    assert!(remote.delivered.is_none());
}

#[test]
fn foreign_instance_or_coding_context_never_unlocks_the_cached_file() {
    let mut s = nodes(true, 32).remove(0);
    s.broadcast(&[8; 32]).unwrap();
    let codec = wavid::Codec::new(&s.storage.membership, s.storage.instance, [8; 32], 32).unwrap();
    let foreign_root = codec.commit_file(vec![8; 32]).unwrap().root();
    ready(&mut s, foreign_root, &[1, 2, 3]);
    assert!(s.delivered.is_none());
    let mut s = nodes(true, 32).remove(0);
    s.broadcast(&[8; 32]).unwrap();
    let root = s.storage.codec.commit_file(vec![8; 32]).unwrap().root();
    for sender in 1..4 {
        s.receive(
            sender,
            wrbc::ProtMsg {
                instance: InstanceId::new(8, Some(0), 0),
                kind: wavid::Kind::Ready(root),
            },
        );
    }
    assert!(s.storage.completed_root.is_none() && s.delivered.is_none());
}

#[test]
fn output_before_local_storage_still_serves_delayed_peer_requests() {
    let mut s = nodes(true, 139).remove(0);
    let data = vec![7; 139];
    s.broadcast(&data).unwrap();
    let init = std::mem::take(&mut s.outgoing)
        .into_iter()
        .filter(|a| a.recipient == 0)
        .collect::<Vec<_>>();
    let root = s.storage.codec.commit_file(data).unwrap().root();
    ready(&mut s, root, &[1, 2, 3]);
    assert!(s.delivered.is_some() && s.storage.stored_root.is_none());
    s.outgoing.clear();
    s.receive(
        2,
        wrbc::ProtMsg {
            instance: s.storage.instance,
            kind: wavid::Kind::Request(root),
        },
    );
    assert!(s.outgoing.is_empty());
    for a in init {
        s.receive(0, a.message);
    }
    assert_eq!(s.storage.stored_root, Some(root));
    assert!(
        s.outgoing
            .iter()
            .any(|a| a.recipient == 2 && matches!(a.message.kind, wavid::Kind::Data { .. }))
    );
    assert!(
        s.outgoing
            .iter()
            .any(|a| matches!(a.message.kind, wavid::Kind::Ack(_)))
    );
    assert_eq!(
        s.events
            .iter()
            .filter(|e| matches!(e, Event::Deliver { .. }))
            .count(),
        1
    );
}

#[test]
fn reordered_full_service_preserves_receivers_and_saves_only_self_retrieval() {
    for bytes in [0, 139, 8192] {
        let mut counts = vec![];
        let codec = nodes(false, bytes).remove(0).storage.codec;
        let saved: u64 = (1..4)
            .map(|owner| {
                let raw = codec.bundle_bytes(owner);
                (raw + 173 * raw.div_ceil(wavid::CHUNK_BYTES)) as u64
            })
            .sum();
        for reuse in [false, true] {
            let mut nodes = nodes(reuse, bytes);
            let data = vec![29; bytes];
            nodes[0].broadcast(&data).unwrap();
            let mut q = VecDeque::new();
            let mut requests = vec![0; 4];
            let mut remote_data = 0u64;
            let mut steps = 0;
            loop {
                for (sender, s) in nodes.iter_mut().enumerate() {
                    for a in std::mem::take(&mut s.outgoing) {
                        if matches!(a.message.kind, wavid::Kind::Request(_)) {
                            requests[sender] += 1;
                        }
                        if sender != a.recipient
                            && matches!(a.message.kind, wavid::Kind::Data { .. })
                        {
                            remote_data += bincode::serialized_size(&a.message).unwrap() + 132;
                        }
                        q.push_back((sender, a));
                    }
                }
                let Some((sender, a)) = (if steps % 3 == 0 {
                    q.pop_front()
                } else {
                    q.pop_back()
                }) else {
                    break;
                };
                nodes[a.recipient].receive(sender, a.message);
                steps += 1;
                assert!(steps < 100000);
            }
            assert!(
                nodes
                    .iter()
                    .all(|s| s.delivered.as_deref() == Some(data.as_slice()))
            );
            assert_eq!(requests[0], if reuse { 0 } else { 4 });
            assert_eq!(&requests[1..], &[4; 3]);
            assert_eq!(nodes[0].storage.result.is_none(), reuse);
            counts.push(remote_data);
        }
        assert_eq!(counts[0] - counts[1], saved);
    }
}
