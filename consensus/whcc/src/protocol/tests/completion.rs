use crate::{Parameters, State, msg::Action};
use wiawvss::{
    Opening, ax,
    certified::{Header, Receipt},
};
#[test]
fn sampling_and_list_versions_bind_context_even_when_quotas_match() {
    use crate::protocol::parameters::{ListBroadcast, SamplingMode};
    let node = super::nodes(&[3; 4], 4, 20000).remove(0);
    let base = Parameters {
        bulk_block_bytes: 128.into(),
        ..Parameters::default()
    };
    let setup = base.setup(&node).unwrap();
    let mut seen = std::collections::BTreeSet::new();
    for sampling_mode in [SamplingMode::TightV1, SamplingMode::LegacyV1] {
        for list_broadcast in [ListBroadcast::FixedChunksV1, ListBroadcast::CodedV1] {
            let p = Parameters {
                sampling_mode,
                list_broadcast,
                ..base.clone()
            };
            assert!(seen.insert(p.context_id(&node, &setup)));
            let state = State::new(&node, p).unwrap();
            assert_eq!(state.sampling.quotas, vec![4; 4]);
            assert_eq!(state.assignments.parameters.quotas, state.sampling.quotas);
            let raw = state.encode_sampling_list(0, &[0, 1, 2, 3]).unwrap();
            assert_eq!(
                raw.len(),
                if list_broadcast == ListBroadcast::FixedChunksV1 {
                    64
                } else {
                    48
                }
            );
        }
    }
    for bad in [
        r#"{"sampling_mode":"adaptive"}"#,
        r#"{"list_broadcast":"auto"}"#,
    ] {
        assert!(serde_json::from_str::<Parameters>(bad).is_err());
    }
}
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
        data: wavid::Codec::with_params(
            &node.weighted_membership().unwrap(),
            instance,
            s.params
                .bound_node(&node, &s.setup)
                .weighted_public_id("wrbc"),
            Header::BYTES,
            Parameters::CONTROL_CODING,
        )
        .unwrap()
        .commit_file(h.encode())
        .unwrap(),
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

#[test]
fn bulk_coding_is_validated_separate_from_control_and_bound_to_context() {
    let node = super::nodes(&[3; 4], 4, 20000).remove(0);
    let default = Parameters {
        bulk_block_bytes: 32.into(),
        ..Parameters::default()
    };
    let setup = default.setup(&node).unwrap();
    for bytes in [32, 34, 128, 510, 4096] {
        let p = Parameters {
            bulk_block_bytes: bytes.into(),
            ..default.clone()
        };
        let state = State::new(&node, p.clone()).unwrap();
        assert!(
            state
                .dealers
                .iter()
                .all(|d| d.codec.parameters().block_bytes == bytes)
        );
        assert!(state.avid_manifest().iter().all(|r|matches!(r,wavid::Request::Register{descriptor,..} if descriptor.coding.block_bytes==bytes)));
        assert!(
            state
                .rbc_manifest()
                .iter()
                .all(|r| matches!(r,wrbc::Request::Register{coding,..} if coding.block_bytes==32))
        );
        if bytes != 32 {
            assert_ne!(
                p.context_id(&node, &setup),
                default.context_id(&node, &setup)
            );
        }
    }
    for bytes in [0, 30, 33, 4098, usize::MAX] {
        assert!(
            Parameters {
                bulk_block_bytes: bytes.into(),
                ..default.clone()
            }
            .validate(&node)
            .is_err()
        );
    }
    assert!(serde_json::from_str::<Parameters>(r#"{"bulk_block_bytes":"auto"}"#).is_err());
}

#[test]
fn boundary_module_frames_are_checked_before_startup_on_frozen_aptos_weights() {
    #[derive(serde::Deserialize)]
    struct Case {
        n: usize,
        weights: Vec<String>,
        threshold: String,
    }
    let cases: Vec<Case> = serde_json::from_str(include_str!(
        "../../../../wiawvss/tests/fixtures/clean-aptos.json"
    ))
    .unwrap();
    for case in cases {
        let weights: Vec<u64> = case.weights.iter().map(|w| w.parse().unwrap()).collect();
        let node = super::nodes(&weights, case.threshold.parse().unwrap(), 20000).remove(0);
        let small = Parameters {
            bulk_block_bytes: 32.into(),
            ..Parameters::default()
        }
        .setup(&node);
        if case.n == 60 {
            assert!(
                small
                    .unwrap_err()
                    .to_string()
                    .contains("fault evidence exceed")
            );
        } else {
            assert!(small.is_ok());
        }
        let params = Parameters {
            bulk_block_bytes: 1024.into(),
            ..Parameters::default()
        };
        let setup = params.setup(&node).unwrap();
        assert!(setup.boundary().is_some());
        assert_eq!(setup.circuit().policy().n(), case.n);
    }
}
