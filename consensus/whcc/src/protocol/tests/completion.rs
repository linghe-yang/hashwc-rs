use crate::{Parameters, State, msg::Action};
use wiawvss::{
    Opening, ax,
    certified::{Header, Receipt},
};
#[test]
fn header_and_receipt_do_not_echo_before_matching_stored_event() {
    let node = super::nodes(&[3; 4], 4, 20000).remove(1);
    let mut s = State::new(&node, Parameters::default()).unwrap();
    let d = 0;
    let instance = s.instance(d, 0);
    let (p, shares) = ax::generate(
        &s.setup,
        &s.dealers[d].context,
        &Opening {
            message: [0; 32],
            randomness: [7; 32],
        },
    )
    .unwrap();
    let prep = s.dealers[d].codec.prepare(&p.encode()).unwrap();
    let h = Header::new(&s.setup, &s.dealers[d].context, prep.root);
    let raw = Receipt::new(&s.setup, &s.dealers[d].codec, &prep, &shares[1])
        .unwrap()
        .encode();
    s.private_packet(
        0,
        network::Packet {
            epoch: 0,
            dealer: d,
            kind: crate::msg::PRIVATE_TOKEN,
            payload: raw,
        },
    )
    .unwrap();
    assert!(s.drain_actions().is_empty());
    s.rbc_event(wrbc::Event::Deliver {
        instance,
        data: h.encode(),
    })
    .unwrap();
    assert!(!s.dealers[d].complete);
    assert!(!s.dealers[d].echoed);
    assert!(
        s.drain_actions()
            .iter()
            .all(|a| !matches!(a, Action::Ra(wra::Request::Input { .. })))
    );
    s.avid_event(wavid::Event::Stored {
        instance,
        root: [0; 32],
    })
    .unwrap();
    assert!(!s.dealers[d].echoed);
    s.avid_event(wavid::Event::Stored {
        instance,
        root: h.root,
    })
    .unwrap();
    assert!(s.dealers[d].echoed);
    assert!(!s.dealers[d].complete);
    assert_eq!(
        s.drain_actions()
            .iter()
            .filter(|a| matches!(a, Action::Ra(wra::Request::Input { value: true, .. })))
            .count(),
        1
    );
    s.avid_event(wavid::Event::Stored {
        instance,
        root: h.root,
    })
    .unwrap();
    assert!(s.drain_actions().is_empty());
    s.ra_event(wra::Event::Output {
        instance,
        value: true,
    })
    .unwrap();
    assert!(s.dealers[d].complete);
}

#[test]
fn weighted_ready_thresholds_are_strict_and_do_not_require_local_echo() {
    let membership = sdc_types::WeightedMembership::new(
        vec![sdc_types::Weight::from(1); 7],
        sdc_types::Weight::from(2),
    )
    .unwrap();
    let instance = sdc_types::InstanceId::new(0, Some(0), 0);
    let header = [9; 32];
    let msg = |kind| wra::ProtMsg {
        instance,
        header_id: header,
        kind,
    };
    let mut ra = wra::State::new(membership.clone(), 6, instance, header).unwrap();
    for sender in 0..5 {
        ra.receive(sender, msg(wra::Kind::Echo(true)));
    }
    assert!(ra.ready_value.is_none());
    assert!(ra.output.is_none());
    ra.receive(0, msg(wra::Kind::Echo(true)));
    assert!(ra.ready_value.is_none());
    ra.receive(5, msg(wra::Kind::Echo(true)));
    assert_eq!(ra.ready_value, Some(true));
    assert!(ra.output.is_none());
    let mut relay = wra::State::new(membership, 6, instance, header).unwrap();
    relay.receive(0, msg(wra::Kind::Ready(true)));
    assert!(relay.ready_value.is_none());
    relay.receive(1, msg(wra::Kind::Ready(true)));
    assert_eq!(relay.ready_value, Some(true));
    assert!(relay.input_value.is_none());
    for sender in 2..5 {
        relay.receive(sender, msg(wra::Kind::Ready(true)));
    }
    assert!(relay.output.is_none());
    relay.receive(5, msg(wra::Kind::Ready(true)));
    assert_eq!(relay.output, Some(true));
}
