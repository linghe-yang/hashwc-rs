use crate::{
    Parameters, RecoveryMode, State,
    msg::{Action, Event},
};
use sdc_types::{Dyadic, Weight};
use wiawvss::certified::{Certificate, Header};

fn params() -> Parameters {
    Parameters {
        recovery_mode: RecoveryMode::Auto,
        reuse_local_dealer: true,
        ..Parameters::default()
    }
}
fn state(id: usize, p: Parameters) -> State {
    State::new(&super::nodes(&[3; 4], 4, 20000).remove(id), p).unwrap()
}
fn deliver_header(s: &mut State, header: Header) {
    let node = super::nodes(&[3; 4], 4, 20000).remove(s.id);
    let instance = s.instance(s.id, 0);
    let codec = wavid::Codec::with_params(
        &node.weighted_membership().unwrap(),
        instance,
        s.params
            .bound_node(&node, &s.setup)
            .weighted_public_id("wrbc"),
        Header::BYTES,
        Parameters::CONTROL_CODING,
    )
    .unwrap();
    s.rbc_event(wrbc::Event::Deliver {
        instance,
        data: codec.commit_file(header.encode()).unwrap(),
    })
    .unwrap();
}
fn complete(s: &mut State) {
    s.ra_event(wra::Event::Output {
        instance: s.instance(s.id, 0),
        value: true,
    })
    .unwrap();
}
fn freeze(s: &mut State) {
    s.gather = Some(vec![]);
    s.binaa_event(wbinaa::Event::DeliverVector {
        instance: s.global(),
        values: (0..s.n)
            .map(|i| Dyadic {
                numerator: Weight::from(u64::from(i == s.id)),
                exponent: 0,
            })
            .collect(),
    })
    .unwrap();
}
fn start(s: &mut State) -> (Header, wavid::Dispersal) {
    s.start().unwrap();
    let actions = s.drain_actions();
    assert!(!actions.iter().any(
        |a| matches!(a,Action::Rbc(wrbc::Request::Broadcast {instance,..}) if instance.slot==1)
    ));
    let prepared = actions
        .iter()
        .find_map(|a| match a {
            Action::Avid(wavid::Request::DisperseCached { prepared, .. }) => Some(prepared.clone()),
            _ => None,
        })
        .unwrap();
    (
        Header::new(&s.setup, &s.dealers[s.id].context, prepared.file().root()),
        prepared,
    )
}
#[test]
fn own_opening_waits_for_matching_header_complete_and_freeze_and_is_publicly_valid() {
    for freeze_first in [false, true] {
        let mut s = state(0, params());
        let (h, _) = start(&mut s);
        assert!(s.local_material.is_some());
        assert!(s.dealers[0].value.is_none());
        if freeze_first {
            freeze(&mut s);
        }
        deliver_header(&mut s, h.clone());
        assert!(s.dealers[0].value.is_none());
        if freeze_first {
            complete(&mut s);
        } else {
            complete(&mut s);
            assert!(s.dealers[0].value.is_none());
            freeze(&mut s);
        }
        assert!(s.coin().is_some());
        assert!(!s.dealers[0].retrieving && s.dealers[0].tokens.is_empty());
        assert!(s.assignments.authorized(0, 0) && !s.remote_authorized(0, 0));
        let cert =
            Certificate::decode(&s.dealers[0].codec, s.dealers[0].terminal.as_ref().unwrap())
                .unwrap();
        assert!(wiawvss::certified::verify(
            &s.setup,
            &s.dealers[0].context,
            &s.dealers[0].codec,
            &h,
            &cert,
            s.contribution_bits()
        ));
        let actions = s.drain_actions();
        assert!(!actions.iter().any(|a|matches!(a,Action::Avid(wavid::Request::Retrieve {instance}) if instance.dealer==Some(0))));
        assert_eq!(actions.iter().filter(|a|matches!(a,Action::Recovery {packet,..} if packet.kind==crate::msg::TERMINAL)).count(),4);
        let events = s.drain_events();
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(e, Event::Coin { .. }))
                .count(),
            1
        );
        complete(&mut s);
        freeze(&mut s);
        assert!(s.drain_events().is_empty());
    }
    let mut s = state(0, params());
    let (mut wrong, _) = start(&mut s);
    wrong.root[0] ^= 1;
    deliver_header(&mut s, wrong);
    complete(&mut s);
    freeze(&mut s);
    assert!(s.dealers[0].value.is_none());
}
#[test]
fn holder_rejects_dealer_self_fetch_and_unselected_fetch_but_serves_selected_remote() {
    let p = params();
    let mut source = state(0, p.clone());
    let (h, prepared) = start(&mut source);
    let holder_app = state(2, p.clone());
    let node = super::nodes(&[3; 4], 4, 20000).remove(2);
    let instance = source.instance(0, 0);
    let descriptor = holder_app
        .avid_manifest()
        .into_iter()
        .find_map(|r| match r {
            wavid::Request::Register {
                instance: i,
                descriptor,
            } if i == instance => Some(descriptor),
            _ => None,
        })
        .unwrap();
    assert_eq!(descriptor.retrievers, vec![1]);
    assert_eq!(holder_app.rbc_manifest().len(), 4);
    let public_id = p
        .bound_node(&node, &holder_app.setup)
        .weighted_public_id("wavid");
    let mut sender = wavid::State::new(
        node.weighted_membership().unwrap(),
        0,
        instance,
        public_id,
        descriptor.clone(),
    )
    .unwrap();
    let mut holder = wavid::State::new(
        node.weighted_membership().unwrap(),
        2,
        instance,
        public_id,
        descriptor,
    )
    .unwrap();
    sender.disperse_cached(prepared).unwrap();
    holder.pin_root(h.root).unwrap();
    for a in sender.outgoing.into_iter().filter(|a| a.recipient == 2) {
        holder.receive(0, a.message);
    }
    assert_eq!(holder.stored_root, Some(h.root));
    holder.accept_completion(h.root).unwrap();
    holder.outgoing.clear();
    for peer in [0, 3] {
        holder.receive(
            peer,
            wavid::ProtMsg {
                instance,
                kind: wavid::Kind::Request(h.root),
            },
        );
        assert!(holder.outgoing.is_empty());
    }
    assert!(holder.retrieve().is_err());
    holder.receive(
        1,
        wavid::ProtMsg {
            instance,
            kind: wavid::Kind::Request(h.root),
        },
    );
    assert!(!holder.outgoing.is_empty());
    assert!(
        holder
            .outgoing
            .iter()
            .all(|a| a.recipient == 1 && matches!(a.message.kind, wavid::Kind::Data { .. }))
    );
}
#[test]
fn config_contexts_bind_mode_reuse_and_table_and_fallback_keeps_sampling() {
    let node = super::nodes(&[3; 4], 4, 20000).remove(0);
    let baseline = Parameters::default();
    let setup = baseline.setup(&node).unwrap();
    let mut seen = std::collections::BTreeSet::new();
    for mode in [
        RecoveryMode::Sampled,
        RecoveryMode::Auto,
        RecoveryMode::ThreeComplement,
    ] {
        for reuse in [false, true] {
            let p = Parameters {
                recovery_mode: mode,
                reuse_local_dealer: reuse,
                ..baseline.clone()
            };
            assert!(seen.insert(p.context_id(&node, &setup)));
            let s = State::new(&node, p).unwrap();
            assert_eq!(
                s.rbc_manifest().len()
                    + s.list_chunk_lengths().iter().map(|l| l / 64).sum::<usize>(),
                if mode == RecoveryMode::Sampled { 8 } else { 4 }
            );
        }
    }
    let s = state(
        0,
        Parameters {
            coverage_bits: 8,
            ..params()
        },
    );
    assert!(s.group_plan.is_none() && s.reuses_local_dealer());
    assert_eq!(
        s.rbc_manifest().len() + s.list_chunk_lengths().iter().map(|l| l / 64).sum::<usize>(),
        8
    );
    assert!(s.avid_manifest().iter().all(
        |r| matches!(r,wavid::Request::Register {descriptor,..} if descriptor.retrievers.is_empty())
    ));
}

#[test]
fn short_root_reconstructs_canonical_header_binds_mode_and_keeps_opening_gates() {
    let mut s = state(
        0,
        Parameters {
            short_root_rbc: true,
            ..params()
        },
    );
    let mut coded = state(0, params());
    assert_ne!(s.context_id, coded.context_id);
    assert!(s.rbc_manifest().is_empty());
    let (h, _) = start(&mut s);
    let event = crate::root_rbc::Event {
        instance: s.instance(0, 0),
        root: h.root,
    };
    coded.root_event(event.clone()).unwrap();
    assert!(coded.dealers[0].header.is_none());
    let mut wrong = event.clone();
    wrong.instance.epoch += 1;
    s.root_event(wrong).unwrap();
    assert!(s.dealers[0].header.is_none());
    s.root_event(event.clone()).unwrap();
    assert_eq!(s.dealers[0].header.as_ref().unwrap().encode(), h.encode());
    assert!(s.dealers[0].value.is_none());
    complete(&mut s);
    assert!(s.dealers[0].value.is_none());
    freeze(&mut s);
    assert!(s.coin().is_some() && s.dealers[0].terminal_sent);
    s.drain_events();
    s.drain_actions();
    s.root_event(event).unwrap();
    assert!(s.drain_events().is_empty() && s.drain_actions().is_empty());
    let legacy = state(
        0,
        Parameters {
            short_root_rbc: true,
            list_broadcast: crate::protocol::parameters::ListBroadcast::CodedV1,
            ..Parameters::default()
        },
    );
    assert_eq!(legacy.rbc_manifest().len(), 4);
    assert!(legacy.rbc_manifest().iter().all(|r| r.instance().slot == 1));
}
