use bincode::Options;
use types::{InstanceId, Weight, WeightedMembership};
use wbinaa::{
    compact::{CompactMsg, MAX_ENCODED_BYTES},
    Entry, Precision, ProtMsg, State,
};

fn message(entries: Vec<Entry>) -> ProtMsg {
    ProtMsg {
        instance: InstanceId::new(0, None, 0),
        round: 2,
        entries,
    }
}
fn sorted(mut p: ProtMsg) -> ProtMsg {
    p.entries.sort_by_key(|e| (e.coordinate, e.code));
    p
}
fn roundtrip(p: ProtMsg) -> Vec<u8> {
    let packed = CompactMsg(p.clone());
    let bytes = packed.encode().unwrap();
    assert_eq!(bytes, bincode::serialize(&packed).unwrap());
    assert_eq!(
        bincode::serialized_size(&packed).unwrap() as usize,
        bytes.len()
    );
    let decoded: CompactMsg = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(1024)
        .reject_trailing_bytes()
        .deserialize(&bytes)
        .unwrap();
    assert_eq!(decoded.0, sorted(p));
    assert_eq!(CompactMsg::decode(&bytes).unwrap(), decoded);
    assert_eq!(decoded.encode().unwrap(), bytes);
    assert!(bytes.len() <= MAX_ENCODED_BYTES);
    bytes
}
fn next(seed: &mut u64) -> u64 {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    *seed
}
#[test]
fn all_single_slots_and_boundary_headers_roundtrip() {
    for coordinate in 0..91 {
        for code in 0..11 {
            let mut p = message(vec![Entry { coordinate, code }]);
            assert_eq!(roundtrip(p.clone()).len(), 6);
            p.instance = InstanceId::new(u64::MAX, None, u64::MAX);
            p.round = 4096;
            assert_eq!(roundtrip(p.clone()).len(), 24);
            if code < 5 && code != 2 && code != 3 {
                p.round = 1;
                assert!(CompactMsg(p).encode().is_err());
            }
        }
    }
}
#[test]
fn every_per_coordinate_slot_combination_and_many_random_batches_roundtrip() {
    // 6 initial states (including absence), 4 second-ECHO1, 4 ECHO2 = 96.
    for a in 0..6 {
        for b in 0..4 {
            for c in 0..4 {
                let mut entries = vec![];
                if a > 0 {
                    entries.push(Entry {
                        coordinate: 90,
                        code: a - 1,
                    });
                }
                if b > 0 {
                    entries.push(Entry {
                        coordinate: 90,
                        code: b + 4,
                    });
                }
                if c > 0 {
                    entries.push(Entry {
                        coordinate: 90,
                        code: c + 7,
                    });
                }
                if !entries.is_empty() {
                    roundtrip(message(entries));
                }
            }
        }
    }
    let mut seed = 20261023;
    for n in [1, 2, 8, 16, 60, 90, 91] {
        for _ in 0..200 {
            let mut entries = vec![];
            for coordinate in 0..n {
                for (base, alphabet) in [(0, 5), (5, 3), (8, 3)] {
                    let d = next(&mut seed) % (alphabet + 1);
                    if d > 0 {
                        entries.push(Entry {
                            coordinate,
                            code: (base + d - 1) as u8,
                        });
                    }
                }
            }
            if entries.is_empty() {
                continue;
            }
            for i in (1..entries.len()).rev() {
                entries.swap(i, (next(&mut seed) as usize) % (i + 1));
            }
            roundtrip(message(entries));
        }
    }
}
#[test]
fn actual_sizes_for_uniform_binary_and_full_three_role_vectors() {
    let uniform = message(
        (0..91)
            .map(|coordinate| Entry {
                coordinate,
                code: 9,
            })
            .collect(),
    );
    assert_eq!(bincode::serialize(&uniform).unwrap().len(), 484);
    assert_eq!(roundtrip(uniform).len(), 7);
    let mut binary = message(
        (0..91)
            .map(|coordinate| Entry {
                coordinate,
                code: 2 + (coordinate % 2) as u8,
            })
            .collect(),
    );
    binary.round = 1;
    assert_eq!(roundtrip(binary).len(), 19);
    let all = message(
        (0..91)
            .flat_map(|coordinate| {
                [
                    Entry {
                        coordinate,
                        code: (coordinate % 5) as u8,
                    },
                    Entry {
                        coordinate,
                        code: 5 + (coordinate % 3) as u8,
                    },
                    Entry {
                        coordinate,
                        code: 8 + (coordinate % 3) as u8,
                    },
                ]
            })
            .collect(),
    );
    assert_eq!(bincode::serialize(&all).unwrap().len(), 1394);
    assert_eq!(roundtrip(all).len(), 70);
}
#[test]
fn reject_invalid_slots_truncation_padding_modes_overflow_and_noncanonical_forms() {
    for p in [
        message(vec![]),
        message(vec![Entry {
            coordinate: 91,
            code: 2,
        }]),
        message(vec![Entry {
            coordinate: 0,
            code: 11,
        }]),
        message(vec![
            Entry {
                coordinate: 0,
                code: 2,
            },
            Entry {
                coordinate: 0,
                code: 3,
            },
        ]),
        ProtMsg {
            round: 0,
            ..message(vec![Entry {
                coordinate: 0,
                code: 2,
            }])
        },
        ProtMsg {
            round: 4097,
            ..message(vec![Entry {
                coordinate: 0,
                code: 2,
            }])
        },
        ProtMsg {
            instance: InstanceId::new(0, Some(0), 0),
            ..message(vec![Entry {
                coordinate: 0,
                code: 2,
            }])
        },
    ] {
        assert!(CompactMsg(p).encode().is_err());
    }
    let valid = roundtrip(message(
        (0..91)
            .map(|coordinate| Entry {
                coordinate,
                code: 2 + (coordinate % 2) as u8,
            })
            .collect(),
    ));
    for end in 0..valid.len() {
        assert!(CompactMsg::decode(&valid[..end]).is_err());
    }
    let mut extra = valid.clone();
    extra.push(0);
    assert!(CompactMsg::decode(&extra).is_err());
    let mut overlong = vec![128, 0];
    overlong.extend_from_slice(&valid[1..]);
    assert!(CompactMsg::decode(&overlong).is_err());
    assert!(CompactMsg::decode(&[255; 1000]).is_err());
    let mut bad = valid.clone();
    bad[3] |= 0x20;
    assert!(CompactMsg::decode(&bad).is_err());
    let mut bad = valid.clone();
    bad[6] |= 0x80;
    assert!(CompactMsg::decode(&bad).is_err());
    let mut bad = valid.clone();
    *bad.last_mut().unwrap() |= 0x80;
    assert!(CompactMsg::decode(&bad).is_err());
    // Unused token 1023 in sparse mode (legal maximum is 1000).
    assert!(CompactMsg::decode(&[0, 0, 1, 0, 255, 3]).is_err());
    // Dense radix-one claim contains an impossible role with an empty palette.
    assert!(CompactMsg::decode(&[0, 0, 1, 0xd0, 0, 0, 4]).is_err());
}
#[test]
fn arbitrary_wire_bytes_never_panic_and_accepted_encodings_are_canonical() {
    let mut seed = 67u64;
    for _ in 0..8000 {
        let len = (next(&mut seed) % 110) as usize;
        let raw: Vec<_> = (0..len).map(|_| next(&mut seed) as u8).collect();
        if let Ok(p) = CompactMsg::decode(&raw) {
            assert_eq!(p.encode().unwrap(), raw);
        }
    }
}
fn drive_pair(weights: &[u64], threshold: u64, bits: u32, absent: &[usize], mut seed: u64) {
    let n = weights.len();
    let m = WeightedMembership::new(
        weights.iter().map(|&w| Weight::from(w)).collect(),
        Weight::from(threshold),
    )
    .unwrap();
    let make = || {
        (0..n)
            .map(|id| {
                State::new(
                    m.clone(),
                    id,
                    InstanceId::new(3, None, 17),
                    Precision::bits(bits),
                )
                .unwrap()
            })
            .collect::<Vec<_>>()
    };
    let mut old = make();
    let mut compact = make();
    for i in 0..n {
        if absent.contains(&i) {
            continue;
        }
        let inputs = (0..n)
            .map(|c| c == 1 || (c > 1 && (c + i) % 3 == 0))
            .collect::<Vec<_>>();
        old[i].start(inputs.clone()).unwrap();
        compact[i].start(inputs).unwrap();
    }
    if let Some(&byzantine) = absent.first() {
        for recipient in 0..n {
            if absent.contains(&recipient) {
                continue;
            }
            for round in (1..=bits).rev() {
                let entries = (0..n as u32)
                    .flat_map(|coordinate| {
                        [
                            Entry {
                                coordinate,
                                code: 2 + (recipient % 2) as u8,
                            },
                            Entry {
                                coordinate,
                                code: if recipient % 2 == 0 { 5 } else { 7 },
                            },
                            Entry {
                                coordinate,
                                code: 9,
                            },
                        ]
                    })
                    .collect();
                let p = ProtMsg {
                    instance: InstanceId::new(3, None, 17),
                    round,
                    entries,
                };
                let decoded = CompactMsg::decode(&roundtrip(p.clone())).unwrap().0;
                for _ in 0..2 {
                    old[recipient].receive(byzantine, p.clone());
                    compact[recipient].receive(byzantine, decoded.clone());
                }
            }
        }
    }
    let mut queue = vec![];
    let mut steps = 0;
    loop {
        for sender in 0..n {
            let a = std::mem::take(&mut old[sender].outgoing);
            let b = std::mem::take(&mut compact[sender].outgoing);
            assert_eq!(a.len(), b.len());
            for (a, b) in a.into_iter().zip(b) {
                assert_eq!(a.recipient, b.recipient);
                assert_eq!(a.message, b.message);
                if !absent.contains(&sender) && !absent.contains(&a.recipient) {
                    queue.push((sender, a));
                }
            }
            assert_eq!(old[sender].output, compact[sender].output);
        }
        if queue.is_empty() {
            break;
        }
        let index = (next(&mut seed) as usize) % queue.len();
        let (sender, a) = queue.swap_remove(index);
        let decoded = CompactMsg::decode(&roundtrip(a.message.clone())).unwrap().0;
        old[a.recipient].receive(sender, a.message.clone());
        compact[a.recipient].receive(sender, decoded.clone());
        // Reordering, duplication and previously completed-round delivery are allowed.
        if steps % 29 == 0 {
            old[a.recipient].receive(sender, a.message);
            compact[a.recipient].receive(sender, decoded);
        }
        steps += 1;
        assert!(steps < 1_000_000);
    }
    assert!(old
        .iter()
        .enumerate()
        .filter(|(i, _)| !absent.contains(i))
        .all(|(_, s)| s.output.is_some()));
}
#[test]
fn compact_and_legacy_transcripts_are_equivalent_under_reordering_and_silence() {
    for seed in [19, 61, 109] {
        drive_pair(&[3; 4], 4, 5, &[3], seed);
        drive_pair(&[10, 1, 1, 1, 1], 4, 4, &[2, 3, 4], seed);
    }
    drive_pair(&[3; 91], 91, 1, &[], 31);
}
