use std::collections::VecDeque;
use types::{InstanceId, Weight, WeightedMembership};
use wbinaa::{Precision, State};
#[test]
fn selected_coordinates_only_send_selected_messages_and_still_tolerate_omission() {
    let membership = WeightedMembership::new(vec![Weight::from(3); 4], Weight::from(4)).unwrap();
    let instance = InstanceId::new(17, None, 0);
    let mut states: Vec<_> = (0..3)
        .map(|id| State::new(membership.clone(), id, instance, Precision::bits(8)).unwrap())
        .collect();
    let mut queue = VecDeque::new();
    for (id, s) in states.iter_mut().enumerate() {
        s.start_selected(vec![false, true, false, true], vec![1, 3])
            .unwrap();
        queue.extend(std::mem::take(&mut s.outgoing).into_iter().map(|x| (id, x)));
    }
    let mut count = 0;
    while let Some((sender, action)) = queue.pop_front() {
        count += 1;
        assert!(count < 10000);
        assert!(action
            .message
            .entries
            .iter()
            .all(|e| [1, 3].contains(&e.coordinate)));
        if action.recipient == 3 {
            continue;
        }
        let s = &mut states[action.recipient];
        s.receive(sender, action.message);
        queue.extend(
            std::mem::take(&mut s.outgoing)
                .into_iter()
                .map(|x| (action.recipient, x)),
        );
    }
    for s in states {
        let out = s.output.unwrap();
        assert_eq!(out.len(), 4);
        for c in [0, 2] {
            assert_eq!(out[c].numerator, Weight::from(0));
        }
        for c in [1, 3] {
            assert_eq!(out[c].numerator, Weight::from(256));
        }
    }
}
