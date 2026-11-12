use std::collections::VecDeque;
use types::{InstanceId, Weight, WeightedMembership};
use wrbc::{Event, State};
fn membership() -> WeightedMembership {
    WeightedMembership::new(vec![Weight::from(3); 4], Weight::from(4)).unwrap()
}
fn drive(states: &mut [State]) {
    let mut queue = VecDeque::new();
    let mut steps = 0;
    loop {
        for (sender, state) in states.iter_mut().enumerate() {
            for a in std::mem::take(&mut state.outgoing) {
                queue.push_back((sender, a));
            }
        }
        let Some((sender, a)) = queue.pop_back() else {
            break;
        };
        states[a.recipient].receive(sender, a.message);
        steps += 1;
        assert!(steps < 100000);
    }
}
#[test]
fn delivery_is_exactly_once_and_empty_is_valid() {
    for data in [vec![], vec![31; 139]] {
        let m = membership();
        let inst = InstanceId::new(0, Some(0), 0);
        let mut nodes: Vec<_> = (0..4)
            .map(|i| State::new(m.clone(), i, inst, [1; 32], data.len()).unwrap())
            .collect();
        nodes[0].broadcast(&data).unwrap();
        drive(&mut nodes);
        for s in &nodes {
            assert_eq!(s.delivered.as_deref(), Some(data.as_slice()));
            assert_eq!(
                s.events
                    .iter()
                    .filter(|e| matches!(e, Event::Deliver { .. }))
                    .count(),
                1
            );
        }
        assert!(nodes[0].broadcast(&data).is_err());
        assert!(nodes[1].broadcast(&data).is_err());
    }
}
#[test]
fn invalid_wavid_never_produces_rbc_delivery() {
    let data = vec![1; 100];
    let m = membership();
    let inst = InstanceId::new(0, Some(0), 0);
    let mut nodes: Vec<_> = (0..4)
        .map(|i| State::new(m.clone(), i, inst, [2; 32], data.len()).unwrap())
        .collect();
    let prepared = nodes[0].storage.codec.prepare(&data).unwrap();
    let mut rows = prepared.rows;
    rows[0][11][0] ^= 1;
    let p = nodes[0].storage.codec.commit_rows(rows).unwrap();
    nodes[0].storage.disperse_prepared(p).unwrap();
    nodes[0].outgoing = std::mem::take(&mut nodes[0].storage.outgoing);
    drive(&mut nodes);
    assert!(nodes.iter().all(|s| s.delivered.is_none() && s.rejected));
}
