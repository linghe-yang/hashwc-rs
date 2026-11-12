use types::{InstanceId, Weight, WeightedMembership};
use wavid::{Codec, CompletionMode, Descriptor, Event, State};
#[test]
fn early_packet_waits_for_authenticated_root() {
    let m = WeightedMembership::new(vec![Weight::from(3); 4], Weight::from(4)).unwrap();
    let instance = InstanceId::new(0, Some(0), 0);
    let data = vec![17; 32768];
    let codec = Codec::new(&m, instance, [8; 32], data.len()).unwrap();
    let prepared = codec.prepare(&data).unwrap();
    let root = prepared.root;
    let descriptor = Descriptor {
        coding: Default::default(),
        file_bytes: data.len(),
        root: None,
        retrievers: vec![1],
        completion: CompletionMode::External,
    };
    let mut dealer = State::new(m.clone(), 0, instance, [8; 32], descriptor.clone()).unwrap();
    let mut receiver = State::new(m, 1, instance, [8; 32], descriptor).unwrap();
    dealer.disperse_prepared(prepared).unwrap();
    let mut packets: Vec<_> = dealer
        .outgoing
        .into_iter()
        .filter(|a| a.recipient == 1)
        .collect();
    assert!(packets.len() > 1);
    packets.reverse();
    for a in packets {
        receiver.receive(0, a.message);
    }
    assert!(receiver.stored_root.is_none());
    assert!(receiver.events.is_empty());
    assert!(receiver.accept_completion(root).is_err());
    receiver.pin_root(root).unwrap();
    assert_eq!(receiver.stored_root, Some(root));
    receiver.pin_root(root).unwrap();
    assert_eq!(
        receiver
            .events
            .iter()
            .filter(|e| matches!(e, Event::Stored { .. }))
            .count(),
        1
    );
    assert!(receiver.pin_root([0; 32]).is_err());
    receiver.accept_completion(root).unwrap();
}
