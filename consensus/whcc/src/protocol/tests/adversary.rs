use crate::{
    Behavior, Event, Parameters, State,
    msg::{Action, PRIVATE_TOKEN, TERMINAL},
};
use network::Packet;
use sdc_types::{Dyadic, Weight};
use wiawvss::{
    Opening, PrivateShare, Public, ax,
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
            Action::Rbc(wrbc::Request::Broadcast { instance, data }) if instance.slot == 0 => {
                Some(data)
            }
            _ => None,
        })
        .unwrap();
    let context = &state.dealers[3].context;
    let public = Public::decode(&state.setup, context, raw).unwrap();
    let shares: Vec<_> = actions
        .iter()
        .filter_map(|a| match a {
            Action::Private { packet, .. } if packet.kind == PRIVATE_TOKEN => {
                Some(PrivateShare::decode(&packet.payload).unwrap())
            }
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
    let node = super::nodes(&[3; 4], 4, 20000).remove(3);
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
        state.dealers[d].public = Some(public);
        state.dealers[d].receipt = Some(shares[3].clone());
        state.dealers[d].complete = false; // Forgery need not wait for the local WRA output.
    }
    let declaration = state
        .sampling
        .encode(state.context_id, 3, &[0, 1, 2, 3])
        .unwrap();
    state.assignments.deliver(3, &declaration);
    state.advance().unwrap();
    // Byzantine messages can arrive before freeze; honest parties must queue them.
    assert!(state.coefficients.is_none());
    let actions = state.drain_actions();
    state.coefficients = Some(vec![
        Dyadic {
            numerator: Weight::from(1),
            exponent: 0
        };
        4
    ]);
    state.advance().unwrap();
    assert!(state.drain_actions().is_empty());
    assert_eq!(actions.len(), 4 * 3);
    for action in actions {
        let Action::Recovery { recipient, packet } = action else {
            panic!("unexpected action")
        };
        assert_ne!(recipient, 3);
        assert_eq!(packet.kind, TERMINAL);
        let d = packet.dealer;
        let public = state.dealers[d].public.as_ref().unwrap();
        let terminal = Terminal::decode(public, &packet.payload).unwrap();
        assert!(!terminal::verify(
            &state.setup,
            &state.dealers[d].context,
            public,
            &terminal
        ));
    }
    for _ in 0..5 {
        state.advance().unwrap();
    }
    assert!(state.drain_actions().is_empty());
    assert!(state.coin().is_none());
}

#[test]
fn forged_opening_is_checked_once_and_cannot_block_an_honest_root_fault() {
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
    Behavior::RecoveryStress.corrupt_public(&mut public);
    let proof = terminal::recover(
        &state.setup,
        &state.dealers[3].context,
        &public,
        &shares[..3],
    )
    .unwrap();
    let forged = Terminal::Success(Opening {
        message: [0; 32],
        randomness: [0; 32],
    })
    .encode(&public);
    let valid = proof.encode(&public);
    state.dealers[3].public = Some(public);
    state.dealers[3].complete = true;

    for sender in [1, 3] {
        let raw = state
            .sampling
            .encode(state.context_id, sender, &[0, 1, 2, 3])
            .unwrap();
        state.assignments.deliver(sender, &raw);
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
    state.coefficients = Some(vec![
        Dyadic {
            numerator: Weight::from(1),
            exponent: 0
        };
        4
    ]);
    state.advance().unwrap();
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
