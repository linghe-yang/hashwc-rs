use types::{InstanceId, Weight, WeightedMembership};
use wbinaa::{Entry, Precision, ProtMsg, State};
fn membership(w: &[u64], t: u64) -> WeightedMembership {
    WeightedMembership::new(
        w.iter().map(|w| Weight::from(*w)).collect(),
        Weight::from(t),
    )
    .unwrap()
}
fn drive(states: &mut [State], absent: &[usize], seed: u64) {
    let mut queue = vec![];
    let mut seed = seed;
    let mut steps = 0;
    loop {
        for (sender, state) in states.iter_mut().enumerate() {
            for a in std::mem::take(&mut state.outgoing) {
                if !absent.contains(&sender) && !absent.contains(&a.recipient) {
                    queue.push((sender, a));
                }
            }
        }
        if queue.is_empty() {
            break;
        }
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let index = seed as usize % queue.len();
        let (sender, a) = queue.swap_remove(index);
        states[a.recipient].receive(sender, a.message);
        steps += 1;
        assert!(steps < 200000);
    }
}
#[test]
fn exact_agreement_and_unanimity_for_all_binary_patterns() {
    for pattern in 0..16 {
        let m = membership(&[3; 4], 4);
        let inst = InstanceId::new(0, None, 0);
        let mut states: Vec<_> = (0..4)
            .map(|i| State::new(m.clone(), i, inst, Precision::bits(8)).unwrap())
            .collect();
        for (i, s) in states.iter_mut().enumerate() {
            s.start(vec![false, true, pattern & (1 << i) != 0, i % 2 == 0])
                .unwrap();
        }
        drive(&mut states, &[], pattern + 9);
        assert!(states.iter().all(|s| s.output.is_some()));
        for c in 0..4 {
            let v: Vec<_> = states
                .iter()
                .map(|s| s.output.as_ref().unwrap()[c].numerator.0.clone())
                .collect();
            let min = v.iter().min().unwrap();
            let max = v.iter().max().unwrap();
            assert!(max - min <= 1u8.into());
            if c == 0 {
                assert!(v.iter().all(|x| *x == 0u8.into()));
            }
            if c == 1 {
                assert!(v.iter().all(|x| *x == 256u16.into()));
            }
        }
    }
}
#[test]
fn future_messages_and_late_start_are_not_lost() {
    let m = membership(&[3; 4], 4);
    let inst = InstanceId::new(0, None, 0);
    let mut states: Vec<_> = (0..4)
        .map(|i| State::new(m.clone(), i, inst, Precision::bits(6)).unwrap())
        .collect();
    for s in &mut states[..3] {
        s.start(vec![true; 4]).unwrap();
    }
    drive(&mut states, &[], 77);
    assert!(states[..3].iter().all(|s| s.output.is_some()));
    assert!(states[3].output.is_none());
    states[3].start(vec![true; 4]).unwrap();
    drive(&mut states, &[], 19);
    assert!(states.iter().all(|s| {
        s.output
            .as_ref()
            .unwrap()
            .iter()
            .all(|d| d.numerator.0 == 64u8.into())
    }));
}
#[test]
fn corrupt_majority_by_count_and_malformed_slots() {
    let m = membership(&[10, 1, 1, 1, 1], 4);
    let inst = InstanceId::new(0, None, 0);
    let mut states: Vec<_> = (0..5)
        .map(|i| State::new(m.clone(), i, inst, Precision::bits(5)).unwrap())
        .collect();
    states[0].start(vec![true; 5]).unwrap();
    states[1].start(vec![true; 5]).unwrap();
    states[0].receive(
        2,
        ProtMsg {
            instance: inst,
            round: 1,
            entries: vec![Entry {
                coordinate: 0,
                code: 0,
            }],
        },
    );
    drive(&mut states, &[2, 3, 4], 7);
    assert!(states[..2].iter().all(|s| {
        s.output
            .as_ref()
            .unwrap()
            .iter()
            .all(|d| d.numerator.0 == 32u8.into())
    }));
}
#[test]
fn precision_validation() {
    assert!(
        wbinaa::round_count(&Precision {
            numerator: Weight::from(0),
            denominator: Weight::from(1)
        })
        .is_err()
    );
    assert_eq!(
        wbinaa::round_count(&Precision {
            numerator: Weight::from(1),
            denominator: Weight::from(3)
        })
        .unwrap(),
        2
    );
}

#[test]
fn equivocating_sender_and_future_rounds_preserve_honest_agreement() {
    for pattern in 0..8u64 {
        let m = membership(&[3; 4], 4);
        let inst = InstanceId::new(0, None, 0);
        let mut nodes: Vec<_> = (0..4)
            .map(|i| State::new(m.clone(), i, inst, Precision::bits(6)).unwrap())
            .collect();
        for (i, node) in nodes[..3].iter_mut().enumerate() {
            for round in (1..=6).rev() {
                let bit = i % 2 == 1;
                let mut entries = vec![];
                for coordinate in 0..4 {
                    entries.push(Entry {
                        coordinate,
                        code: if round == 1 && bit { 3 } else { 2 },
                    });
                    entries.push(Entry {
                        coordinate,
                        code: if bit { 5 } else { 7 },
                    });
                    entries.push(Entry {
                        coordinate,
                        code: 9,
                    });
                }
                let message = ProtMsg {
                    instance: inst,
                    round,
                    entries,
                };
                node.receive(3, message.clone());
                node.receive(3, message);
            }
            node.start(vec![false, true, pattern & (1 << i) != 0, i % 2 == 0])
                .unwrap();
        }
        drive(&mut nodes, &[3], pattern + 27);
        assert!(nodes[..3].iter().all(|s| s.output.is_some()));
        for coordinate in 0..4 {
            let values: Vec<_> = nodes[..3]
                .iter()
                .map(|s| s.output.as_ref().unwrap()[coordinate].numerator.0.clone())
                .collect();
            assert!(values.iter().max().unwrap() - values.iter().min().unwrap() <= 1u8.into());
            if coordinate == 0 {
                assert!(values.iter().all(|v| *v == 0u8.into()));
            }
            if coordinate == 1 {
                assert!(values.iter().all(|v| *v == 64u8.into()));
            }
        }
    }
}

#[test]
fn rounded_threshold_preserves_unanimity_and_agreement_with_one_silent_party() {
    for w in [[1u64; 4], [1, 1, 1, 2], [1, 2, 2, 2], [2; 4]] {
        let t = (w.iter().sum::<u64>() + 2) / 3;
        let absent = if w == [1; 4] || w == [1, 1, 1, 2] {
            0
        } else {
            1
        };
        for pattern in 0..16 {
            let m = membership(&w, t);
            let mut states: Vec<_> = (0..4)
                .map(|i| {
                    State::new(
                        m.clone(),
                        i,
                        InstanceId::new(0, None, 0),
                        Precision::bits(6),
                    )
                    .unwrap()
                })
                .collect();
            for (i, s) in states.iter_mut().enumerate() {
                if i != absent {
                    s.start(vec![false, true, pattern & (1 << i) != 0, i % 2 == 0])
                        .unwrap();
                }
            }
            drive(&mut states, &[absent], pattern + 71);
            let honest: Vec<_> = states
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != absent)
                .map(|(_, s)| s.output.as_ref().unwrap())
                .collect();
            for c in 0..4 {
                let values: Vec<_> = honest.iter().map(|v| v[c].numerator.0.clone()).collect();
                assert!(values.iter().max().unwrap() - values.iter().min().unwrap() <= 1u8.into());
                if c == 0 {
                    assert!(values.iter().all(|v| *v == 0u8.into()));
                }
                if c == 1 {
                    assert!(values.iter().all(|v| *v == 64u8.into()));
                }
            }
        }
    }
}
