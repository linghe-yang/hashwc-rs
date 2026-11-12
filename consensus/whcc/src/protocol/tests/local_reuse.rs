use crate::{
    Parameters, State,
    msg::{Action, Event, RECOVERY_TOKEN, TERMINAL},
};
use sdc_types::{Dyadic, Weight};
use wiawvss::certified::{Certificate, Header};

fn state() -> State {
    State::new(
        &super::nodes(&[1, 2, 4, 5], 4, 20000).remove(0),
        Parameters {
            coverage_bits: 1,
            short_root_rbc: true,
            reuse_local_dealer: true,
            bulk_block_bytes: 128.into(),
            ..Parameters::default()
        },
    )
    .unwrap()
}
fn start(s: &mut State, hit: bool) -> (Header, Vec<u8>, Vec<Action>) {
    let d = s.sampling.quotas[0];
    assert!(d > 0 && d < s.n);
    let list = if hit {
        (0..d).collect()
    } else {
        (1..=d).collect()
    };
    s.start_with_list(list).unwrap();
    let actions = s.drain_actions();
    let declaration = actions
        .iter()
        .find_map(|a| match a {
            Action::Rbc(wrbc::Request::Broadcast { instance, data }) if instance.slot == 1 => {
                Some(data.clone())
            }
            _ => None,
        })
        .unwrap();
    let file = actions
        .iter()
        .find_map(|a| match a {
            Action::Avid(wavid::Request::DisperseCached { prepared, .. }) => Some(prepared.file()),
            _ => None,
        })
        .unwrap();
    (
        Header::new(&s.setup, &s.dealers[0].context, file.root()),
        declaration,
        actions,
    )
}
fn header(s: &mut State, h: &Header) {
    s.root_event(crate::root_rbc::Event {
        instance: s.instance(0, 0),
        root: h.root,
    })
    .unwrap();
}
fn complete(s: &mut State) {
    s.ra_event(wra::Event::Output {
        instance: s.instance(0, 0),
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
                numerator: Weight::from(u64::from(i == 0)),
                exponent: 0,
            })
            .collect(),
    })
    .unwrap();
}
fn list(s: &mut State, party: usize, bytes: &[u8]) {
    s.list_event(crate::root_rbc::chunks::Event {
        instance: s.instance(party, 1),
        data: bytes.to_vec(),
    })
    .unwrap();
}

#[test]
fn sampled_self_reuse_requires_all_four_gates_in_every_valid_order() {
    // Header must precede RA Complete; list and whole-vector Freeze may be
    // arbitrarily delayed. These are logical event orders, with no timer.
    let mut cases = 0;
    for a in 0..4 {
        for b in 0..4 {
            for c in 0..4 {
                for d in 0..4 {
                    let order = [a, b, c, d];
                    if (0..4).any(|i| (i + 1..4).any(|j| order[i] == order[j]))
                        || order.iter().position(|&v| v == 0) > order.iter().position(|&v| v == 1)
                    {
                        continue;
                    }
                    let mut s = state();
                    let (h, declaration, _) = start(&mut s, true);
                    assert!(s.local_material.is_some());
                    assert!(!s.assignments.authorized(0, 0));
                    assert!(s.dealers[0].value.is_none());
                    for (i, event) in order.into_iter().enumerate() {
                        match event {
                            0 => header(&mut s, &h),
                            1 => complete(&mut s),
                            2 => freeze(&mut s),
                            3 => list(&mut s, 0, &declaration),
                            _ => unreachable!(),
                        }
                        if i < 3 {
                            assert!(s.dealers[0].value.is_none() && s.coin().is_none());
                        }
                    }
                    assert!(s.coin().is_some() && s.dealers[0].terminal_sent);
                    assert!(s.assignments.authorized(0, 0) && !s.remote_authorized(0, 0));
                    assert!(s.dealers[0].tokens.is_empty() && !s.dealers[0].retrieving);
                    let cert = Certificate::decode(
                        &s.dealers[0].codec,
                        s.dealers[0].terminal.as_ref().unwrap(),
                    )
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
                    assert!(!actions.iter().any(|a| matches!(a,Action::Avid(wavid::Request::Retrieve{instance}) if instance.dealer==Some(0))));
                    assert!(!actions.iter().any(|a| matches!(a,Action::Avid(wavid::Request::Authorize{instance,retrievers}) if instance.dealer==Some(0) && retrievers.contains(&0))));
                    assert_eq!(
                        actions
                            .iter()
                            .filter(
                                |a| matches!(a,Action::Recovery{packet,..} if packet.kind==TERMINAL)
                            )
                            .count(),
                        s.n
                    );
                    let events = s.drain_events();
                    let f = events
                        .iter()
                        .position(|e| matches!(e, Event::Frozen { .. }))
                        .unwrap();
                    let t = events
                        .iter()
                        .position(|e| matches!(e, Event::Terminal { dealer: 0, .. }))
                        .unwrap();
                    assert!(f < t);
                    list(&mut s, 0, &declaration);
                    complete(&mut s);
                    freeze(&mut s);
                    assert!(s.drain_events().is_empty() && s.drain_actions().is_empty());
                    cases += 1;
                }
            }
        }
    }
    assert_eq!(cases, 12);
}

#[test]
fn absent_invalid_or_foreign_assignment_and_wrong_root_cannot_open_local_value() {
    for case in 0..5 {
        let mut s = state();
        let (mut h, mut declaration, _) = start(&mut s, case != 0);
        if case == 0 {
            assert!(s.local_material.is_none());
        }
        if case == 1 {
            declaration[0] ^= 1;
        } // Foreign invocation's declaration.
        if case == 2 {
            declaration.pop();
        } // Missing chunk cannot authorize.
        if case == 3 {
            h.root[0] ^= 1;
        }
        header(&mut s, &h);
        complete(&mut s);
        freeze(&mut s);
        if case != 4 {
            list(&mut s, 0, &declaration);
        } // Missing list, despite local draw.
        assert!(s.dealers[0].value.is_none() && !s.dealers[0].terminal_sent);
        assert!(!s.dealers[0].retrieving);
        assert!(
            !s.drain_actions()
                .iter()
                .any(|a| matches!(a,Action::Recovery{packet,..} if packet.kind==TERMINAL))
        );
    }
}

#[test]
fn supplied_ax_has_no_honest_local_provenance() {
    let mut s = state();
    let opening = wiawvss::Opening {
        message: [0; 32],
        randomness: [5; 32],
    };
    let (mut public, shares) =
        wiawvss::ax::generate(&s.setup, &s.dealers[0].context, &opening).unwrap();
    public.base.tag[0] ^= 1;
    let chosen = (0..s.sampling.quotas[0]).collect::<Vec<_>>();
    let declaration = s.encode_sampling_list(0, &chosen).unwrap();
    s.start_material(chosen, public, shares).unwrap();
    assert!(s.local_material.is_none());
    let actions = s.drain_actions();
    let root = actions
        .iter()
        .find_map(|a| match a {
            Action::Avid(wavid::Request::DisperseCached { prepared, .. }) => {
                Some(prepared.file().root())
            }
            _ => None,
        })
        .unwrap();
    let h = Header::new(&s.setup, &s.dealers[0].context, root);
    header(&mut s, &h);
    complete(&mut s);
    freeze(&mut s);
    list(&mut s, 0, &declaration);
    assert!(s.dealers[0].value.is_none() && !s.dealers[0].terminal_sent);
}

#[test]
fn self_terminal_keeps_late_remote_token_service_after_coin_output() {
    let mut s = state();
    let (h, declaration, actions) = start(&mut s, true);
    let private = actions
        .into_iter()
        .find_map(|a| match a {
            Action::Private {
                recipient: 0,
                packet,
            } => Some(packet),
            _ => None,
        })
        .unwrap();
    header(&mut s, &h);
    complete(&mut s);
    freeze(&mut s);
    list(&mut s, 0, &declaration);
    assert!(s.coin().is_some());
    s.drain_actions();
    s.drain_events();
    // The local private receipt can arrive even after the local terminal/coin.
    s.private_packet(0, private).unwrap();
    assert!(
        !s.drain_actions()
            .iter()
            .any(|a| matches!(a,Action::Recovery{packet,..} if packet.kind==RECOVERY_TOKEN))
    );
    let chosen = (0..s.sampling.quotas[1]).collect::<Vec<_>>();
    let bytes = s.encode_sampling_list(1, &chosen).unwrap();
    list(&mut s, 1, &bytes);
    let actions = s.drain_actions();
    assert_eq!(actions.iter().filter(|a|matches!(a,Action::Recovery{recipient:1,packet} if packet.dealer==0 && packet.kind==RECOVERY_TOKEN)).count(),1);
    assert!(s.dealers[0].served[1] && !s.dealers[0].served[0]);
    list(&mut s, 1, &bytes);
    assert!(s.drain_actions().is_empty());
}
