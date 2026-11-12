use crate::{
    Behavior, Event, Parameters, State,
    msg::{Action, PRIVATE_TOKEN, TERMINAL},
};
use network::Packet;
use sdc_types::{Dyadic, Weight};
use wiawvss::{
    Opening, PrivateShare, Public, ax,
    certified::{self, Certificate, Evidence, Header, Receipt},
    terminal::{self, Terminal},
};

#[test]
fn corrupt_dealer_passes_share_checks_but_requires_verifiable_root_fault() {
    let node = super::nodes(&[3; 4], 4, 20000).remove(3);
    let mut state = State::new(&node, Parameters::default()).unwrap();
    state.behavior = Behavior::RecoveryStress;
    state.start().unwrap();
    let actions = state.drain_actions();
    let raw = actions
        .iter()
        .find_map(|a| match a {
            Action::Avid(wavid::Request::DisperseCached { instance, prepared })
                if instance.slot == 0 =>
            {
                Some(prepared.file().as_ref())
            }
            _ => None,
        })
        .unwrap();
    let context = &state.dealers[3].context;
    let public = Public::decode(&state.setup, context, raw).unwrap();
    let shares: Vec<_> = actions
        .iter()
        .filter_map(|a| match a {
            Action::Private { packet, .. } if packet.kind == PRIVATE_TOKEN => Some(
                PrivateShare::decode(
                    &Receipt::decode(&state.dealers[3].codec, &packet.payload)
                        .unwrap()
                        .share,
                )
                .unwrap(),
            ),
            _ => None,
        })
        .collect();
    assert_eq!(shares.len(), 4);
    assert!(
        shares
            .iter()
            .all(|s| ax::verify_share(&state.setup, context, &public, s))
    );
    let proof = terminal::recover(&state.setup, context, &public, &shares[..3]).unwrap();
    assert!(matches!(proof, Terminal::RootFault { .. }));
    assert!(terminal::verify(&state.setup, context, &public, &proof));
}

#[test]
fn adversary_withholds_tokens_and_uses_each_authorized_terminal_slot_once() {
    for bad in 0..4 {
        let node = super::nodes(&[3; 4], 4, 20000).remove(bad);
        let mut state = State::new(&node, Parameters::default()).unwrap();
        state.behavior = Behavior::RecoveryStress;
        for d in 0..4 {
            let (public, shares) = ax::generate(
                &state.setup,
                &state.dealers[d].context,
                &Opening {
                    message: [0; 32],
                    randomness: [7; 32],
                },
            )
            .unwrap();
            let prep = state.dealers[d].codec.prepare(&public.encode()).unwrap();
            state.dealers[d].header = Some(Header::new(
                &state.setup,
                &state.dealers[d].context,
                prep.root,
            ));

            state.dealers[d].receipt = Some(shares[bad].clone());
            state.dealers[d].complete = false; // Forgery need not wait for the local WRA output.
        }
        let declaration = state.encode_sampling_list(bad, &[0, 1, 2, 3]).unwrap();
        state.install_assignments(bad, &declaration);
        state.advance().unwrap();
        // Byzantine messages can arrive before freeze; honest parties must queue them.
        assert!(state.coefficients.is_none());
        let actions = state.drain_actions();
        assert_eq!(
            state
                .drain_events()
                .iter()
                .filter(|e| matches!(e, Event::AdversarialTerminal { recipients: 3, .. }))
                .count(),
            4
        );
        state.gather = Some(vec![]);
        state
            .binaa_event(wbinaa::Event::DeliverVector {
                instance: state.global(),
                values: vec![
                    Dyadic {
                        numerator: Weight::from(1),
                        exponent: 0
                    };
                    4
                ],
            })
            .unwrap();
        assert!(state.drain_actions().is_empty());
        assert_eq!(
            actions
                .iter()
                .filter(|a| matches!(a, Action::Avid(wavid::Request::Retrieve { .. })))
                .count(),
            4
        );
        let actions = actions
            .into_iter()
            .filter(|a| !matches!(a, Action::Avid(_)))
            .collect::<Vec<_>>();
        assert_eq!(actions.len(), 4 * 3);
        for action in actions {
            let Action::Recovery { recipient, packet } = action else {
                panic!("unexpected action")
            };
            assert_ne!(recipient, bad);
            assert_eq!(packet.kind, TERMINAL);
            let d = packet.dealer;
            let dealer = &state.dealers[d];
            let cert = Certificate::decode(&dealer.codec, &packet.payload).unwrap();
            assert!(!certified::verify(
                &state.setup,
                &dealer.context,
                &dealer.codec,
                dealer.header.as_ref().unwrap(),
                &cert,
                state.contribution_bits()
            ));
        }
        for _ in 0..5 {
            state.advance().unwrap();
        }
        assert!(state.drain_actions().is_empty());
        assert!(state.coin().is_none());
    }
}

#[test]
fn forged_opening_is_checked_once_and_cannot_block_an_honest_root_or_module_fault() {
    for module_fault in [false, true] {
        let node = super::nodes(&[3; 4], 4, 20000).remove(0);
        let mut state = State::new(&node, Parameters::default()).unwrap();
        let (mut public, shares) = ax::generate(
            &state.setup,
            &state.dealers[3].context,
            &Opening {
                message: [0; 32],
                randomness: [7; 32],
            },
        )
        .unwrap();
        if module_fault {
            let output = state.setup.circuit().output();
            let index = state.setup.boundary().unwrap().index(output).unwrap();
            public.base.wires[index][0] ^= 1;
        } else {
            Behavior::RecoveryStress.corrupt_public(&mut public);
        }
        let proof = terminal::recover(
            &state.setup,
            &state.dealers[3].context,
            &public,
            &shares[..3],
        )
        .unwrap();
        assert_eq!(matches!(proof, Terminal::ModuleFault { .. }), module_fault);
        let prepared = state.dealers[3].codec.prepare(&public.encode()).unwrap();
        let header = Header::new(&state.setup, &state.dealers[3].context, prepared.root);
        let forged = Certificate {
            header_id: header.id(),
            evidence: Evidence::Success(Opening {
                message: [0; 32],
                randomness: [0; 32],
            }),
        }
        .encode();
        let valid = certified::certify(
            &state.setup,
            &state.dealers[3].codec,
            &header,
            &prepared,
            proof,
        )
        .unwrap()
        .encode();
        state.dealers[3].header = Some(header);
        state.dealers[3].file = Some(state.dealers[3].codec.commit_file(public.encode()).unwrap());
        state.dealers[3].complete = true;

        for sender in [1, 2, 3] {
            let raw = state.encode_sampling_list(sender, &[0, 1, 2, 3]).unwrap();
            state.install_assignments(sender, &raw);
        }
        let packet = |payload| Packet {
            epoch: 0,
            dealer: 3,
            kind: TERMINAL,
            payload,
        };
        for _ in 0..10 {
            state.recovery_packet(3, packet(forged.clone())).unwrap();
        }
        assert!(
            state
                .drain_events()
                .iter()
                .all(|e| !matches!(e, Event::TerminalChecked { .. }))
        );
        assert!(state.dealers[3].value.is_none());
        state.gather = Some(vec![]);
        state
            .binaa_event(wbinaa::Event::DeliverVector {
                instance: state.global(),
                values: vec![
                    Dyadic {
                        numerator: Weight::from(1),
                        exponent: 0
                    };
                    4
                ],
            })
            .unwrap();
        let checks = state
            .drain_events()
            .into_iter()
            .filter(|e| {
                matches!(
                    e,
                    Event::TerminalChecked {
                        sender: 3,
                        decoded: true,
                        accepted: false,
                        ..
                    }
                )
            })
            .count();
        assert_eq!(checks, 1);
        assert!(state.dealers[3].value.is_none());
        // Another authorized sender repeats the rejected bytes. This must remain a
        // rejection and must not consume the independent honest sender's allowance.
        state.recovery_packet(2, packet(forged)).unwrap();
        assert!(state.dealers[3].value.is_none());
        assert!(state.drain_events().iter().any(|e| matches!(
            e,
            Event::TerminalChecked {
                sender: 2,
                decoded: true,
                accepted: false,
                ..
            }
        )));
        state.recovery_packet(1, packet(valid)).unwrap();
        assert_eq!(state.dealers[3].value, Some(0u8.into()));
        assert!(state.drain_events().iter().any(|e| matches!(
            e,
            Event::Terminal {
                dealer: 3,
                rejected: true
            }
        )));
    }
}
