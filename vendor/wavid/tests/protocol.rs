use std::collections::{BTreeMap, VecDeque};
use types::{InstanceId, Weight, WeightedMembership};
use wavid::{Codec, CompletionMode, Descriptor, Event, Retrieval, State};
fn membership(w: &[u64], t: u64) -> WeightedMembership {
    WeightedMembership::new(
        w.iter().map(|w| Weight::from(*w)).collect(),
        Weight::from(t),
    )
    .unwrap()
}
fn states(
    m: WeightedMembership,
    data: &[u8],
    mode: CompletionMode,
    root: Option<[u8; 32]>,
) -> Vec<State> {
    let inst = InstanceId::new(1, Some(0), 0);
    (0..m.n())
        .map(|i| {
            State::new(
                m.clone(),
                i,
                inst,
                [8; 32],
                Descriptor {
                    coding: Default::default(),
                    file_bytes: data.len(),
                    root,
                    retrievers: (0..m.n()).collect(),
                    completion: mode,
                },
            )
            .unwrap()
        })
        .collect()
}
fn drive(states: &mut [State], absent: &[usize], reverse: bool) {
    let mut queue = VecDeque::new();
    let mut steps = 0;
    loop {
        for (sender, state) in states.iter_mut().enumerate() {
            for a in std::mem::take(&mut state.outgoing) {
                if !absent.contains(&sender) && !absent.contains(&a.recipient) {
                    queue.push_back((sender, a));
                }
            }
        }
        let next = if reverse {
            queue.pop_back()
        } else {
            queue.pop_front()
        };
        let Some((sender, a)) = next else {
            break;
        };
        states[a.recipient].receive(sender, a.message);
        steps += 1;
        assert!(steps < 100000);
    }
}
#[test]
fn separate_completion_retrieval_and_empty_file() {
    for data in [vec![], vec![42; 531]] {
        let mut nodes = states(membership(&[3; 4], 4), &data, CompletionMode::Storage, None);
        nodes[0].disperse(&data).unwrap();
        drive(&mut nodes, &[], true);
        assert!(nodes
            .iter()
            .all(|s| s.completed_root.is_some() && s.result.is_none()));
        for s in &mut nodes {
            s.retrieve().unwrap();
        }
        drive(&mut nodes, &[], false);
        for s in &nodes {
            assert!(matches!(&s.result,Some(Retrieval::File(x))if *x==data));
            assert_eq!(
                s.events
                    .iter()
                    .filter(|e| matches!(e, Event::Result { .. }))
                    .count(),
                1
            );
        }
    }
}
#[test]
fn low_weight_byzantine_majority_does_not_block() {
    let data = vec![91; 201];
    let mut nodes = states(
        membership(&[10, 1, 1, 1, 1], 4),
        &data,
        CompletionMode::Storage,
        None,
    );
    nodes[0].disperse(&data).unwrap();
    nodes[0].retrieve().unwrap();
    nodes[1].retrieve().unwrap();
    drive(&mut nodes, &[2, 3, 4], true);
    assert!(nodes[..2]
        .iter()
        .all(|s| matches!(&s.result,Some(Retrieval::File(x))if *x==data)));
}
#[test]
fn late_authorization_after_output_is_served() {
    let data = vec![19; 237];
    let m = membership(&[3; 4], 4);
    let inst = InstanceId::new(1, Some(0), 0);
    let mut nodes: Vec<State> = (0..4)
        .map(|i| {
            State::new(
                m.clone(),
                i,
                inst,
                [8; 32],
                Descriptor {
                    coding: Default::default(),
                    file_bytes: data.len(),
                    root: None,
                    retrievers: vec![0, 1, 2],
                    completion: CompletionMode::Storage,
                },
            )
            .unwrap()
        })
        .collect();
    nodes[0].disperse(&data).unwrap();
    nodes[0].retrieve().unwrap();
    drive(&mut nodes, &[], true);
    assert!(nodes[0].result.is_some());
    assert!(nodes[3].retrieve().is_err());
    nodes[3].authorize(vec![3]).unwrap();
    nodes[3].retrieve().unwrap();
    drive(&mut nodes, &[], false);
    assert!(nodes[3].result.is_none());
    for s in &mut nodes[..3] {
        s.authorize(vec![3]).unwrap();
    }
    nodes[3].retrieve().unwrap();
    drive(&mut nodes, &[], false);
    assert!(matches!(&nodes[3].result,Some(Retrieval::File(x))if *x==data));
    assert!(
        nodes[0]
            .events
            .iter()
            .filter(|e| matches!(e, Event::Result { .. }))
            .count()
            == 1
    );
}
#[test]
fn external_joint_completion_uses_no_storage_quorum() {
    let data = vec![7; 55];
    let m = membership(&[3; 4], 4);
    let inst = InstanceId::new(1, Some(0), 0);
    let codec = Codec::new(&m, inst, [8; 32], data.len()).unwrap();
    let prepared = codec.prepare(&data).unwrap();
    let root = prepared.root;
    let mut nodes = states(m, &data, CompletionMode::External, Some(root));
    nodes[0].disperse_prepared(prepared).unwrap();
    drive(&mut nodes, &[], false);
    assert!(nodes
        .iter()
        .all(|s| s.stored_root == Some(root) && s.completed_root.is_none()));
    for s in &mut nodes {
        s.accept_completion(root).unwrap();
        s.retrieve().unwrap();
    }
    drive(&mut nodes, &[], true);
    assert!(nodes
        .iter()
        .all(|s| matches!(&s.result,Some(Retrieval::File(x))if *x==data)));
}
#[test]
fn coding_fault_is_public_and_false_accusation_fails() {
    let data = vec![5; 100];
    let mut nodes = states(membership(&[3; 4], 4), &data, CompletionMode::Storage, None);
    let prepared = nodes[0].codec.prepare(&data).unwrap();
    let mut rows = prepared.rows;
    rows[0][11][0] ^= 1;
    let bad = nodes[0].codec.commit_rows(rows).unwrap();
    let bad_root = bad.root;
    nodes[0].disperse_prepared(bad).unwrap();
    for s in &mut nodes {
        s.retrieve().unwrap();
    }
    drive(&mut nodes, &[], false);
    for s in &nodes {
        match s.result.as_ref().unwrap() {
            Retrieval::Invalid(proof) => {
                assert!(s.codec.verify_fault(bad_root, proof));
                assert!(!s.codec.verify_fault([0; 32], proof));
            }
            _ => panic!("bad encoding delivered"),
        }
    }
}
#[test]
fn systematic_sources_padding_and_gf16_capacity() {
    let m = membership(&vec![3; 150], 150);
    let codec = Codec::new(&m, InstanceId::new(0, Some(0), 1), [1; 32], 80).unwrap();
    assert_eq!(codec.m, 450);
    let data = vec![17; 80];
    let p = codec.prepare(&data).unwrap();
    assert_eq!(p.rows[0][0], [17; 32]);
    let opening = codec.source_opening(&p, 1).unwrap();
    assert!(codec.verify_source(p.root, &opening));
    let small = Codec::new(
        &membership(&[3; 4], 4),
        InstanceId::new(0, Some(0), 1),
        [1; 32],
        1,
    )
    .unwrap();
    let p = small.commit_rows(vec![vec![vec![1; 32]; small.m]]).unwrap();
    let mut rows = vec![BTreeMap::new()];
    for bundle in &p.bundles {
        for f in &bundle.stripes[0] {
            rows[0].insert(f.index, f.clone());
        }
    }
    match small
        .recover(p.root, &p.bundles[0].directory, &rows)
        .unwrap()
        .unwrap()
    {
        Retrieval::Invalid(proof @ wavid::StorageFault::Padding(_)) => {
            assert!(small.verify_fault(p.root, &proof))
        }
        _ => panic!("expected padding evidence"),
    }
}
#[test]
fn missing_data_never_becomes_invalid() {
    let data = vec![1; 65];
    let mut nodes = states(membership(&[3; 4], 4), &data, CompletionMode::Storage, None);
    for s in &mut nodes {
        s.retrieve().unwrap();
    }
    drive(&mut nodes, &[], false);
    assert!(nodes
        .iter()
        .all(|s| s.result.is_none() && s.completed_root.is_none()));
    let instance = nodes[0].instance;
    nodes[0].receive(
        1,
        wavid::ProtMsg {
            instance,
            kind: wavid::Kind::Init {
                index: 0,
                bytes: vec![0; 100],
            },
        },
    );
    assert!(nodes[0].stored_root.is_none());
}
