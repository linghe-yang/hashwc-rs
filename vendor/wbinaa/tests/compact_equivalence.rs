//! The frozen pre-optimization codec defines the same wire language.
use bincode::Options;
use types::InstanceId;
use wbinaa::{compact::CompactMsg, Entry, ProtMsg};
#[allow(dead_code)]
#[path = "support/compact_v1.rs"]
mod reference;
fn next(seed: &mut u64) -> u64 {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    *seed
}
fn compare(raw: &[u8]) {
    let old = reference::CompactMsg::decode(raw).ok().map(|p| p.0);
    let new = CompactMsg::decode(raw).ok().map(|p| p.0);
    assert_eq!(new, old, "wire: {raw:?}");
    let strict = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(100)
        .reject_trailing_bytes()
        .deserialize::<CompactMsg>(raw)
        .ok()
        .map(|p| p.0);
    assert_eq!(strict, old, "serde wire: {raw:?}");
}
#[test]
fn old_and_new_bytes_and_acceptance_match_for_valid_mutated_and_random_inputs() {
    let mut seed = 20261024;
    let mut checked = 0;
    let mut valid = 0;
    for n in [1, 2, 3, 8, 16, 60, 90, 91] {
        for pattern in 0..32 {
            let mut entries = vec![];
            for coordinate in 0..n {
                for (start, alphabet) in [(0, 5), (5, 3), (8, 3)] {
                    let v = match pattern {
                        0 => {
                            if start == 8 {
                                2
                            } else {
                                0
                            }
                        }
                        1 => {
                            if start == 0 {
                                3 + coordinate % 2
                            } else {
                                0
                            }
                        }
                        2 => 1 + coordinate % alphabet,
                        3 => {
                            if coordinate + 1 == n {
                                alphabet
                            } else {
                                0
                            }
                        }
                        _ => (next(&mut seed) as u32) % (alphabet + 1),
                    };
                    if v > 0 {
                        entries.push(Entry {
                            coordinate,
                            code: (start + v - 1) as u8,
                        });
                    }
                }
            }
            if entries.is_empty() {
                continue;
            }
            let msg = ProtMsg {
                instance: InstanceId::new(
                    [0, 127, 128, u64::MAX][pattern % 4],
                    None,
                    [u64::MAX, 16383, 16384, 0][pattern % 4],
                ),
                round: if pattern == 1 { 1 } else { 4096 },
                entries,
            };
            let old = reference::CompactMsg(msg.clone()).encode().unwrap();
            let new = CompactMsg(msg.clone()).encode().unwrap();
            assert_eq!(old, new);
            let mut reversed = msg;
            reversed.entries.reverse();
            assert_eq!(CompactMsg(reversed).encode().unwrap(), old);
            compare(&old);
            checked += 1;
            valid += 1;
            for end in 0..old.len() {
                compare(&old[..end]);
                checked += 1;
            }
            for i in 0..old.len() {
                for bit in 0..8 {
                    let mut modified = old.clone();
                    modified[i] ^= 1 << bit;
                    compare(&modified);
                    checked += 1;
                }
            }
            let mut extra = old;
            extra.push(0);
            compare(&extra);
            checked += 1;
        }
    }
    for _ in 0..50_000 {
        let len = (next(&mut seed) % 111) as usize;
        let raw: Vec<_> = (0..len).map(|_| next(&mut seed) as u8).collect();
        compare(&raw);
        checked += 1;
    }
    eprintln!("compact differential: {valid} valid messages; {checked} acceptance comparisons");
}
#[test]
fn all_u64_prefix_boundaries_and_invalid_local_messages_match_reference() {
    for value in [0, 1, 127, 128, 16383, 16384, u32::MAX as u64, u64::MAX] {
        for code in 0..=11 {
            for round in [0, 1, 2, 4096, 4097] {
                for coordinate in [0, 90, 91] {
                    let msg = ProtMsg {
                        instance: InstanceId::new(value, None, value),
                        round,
                        entries: vec![Entry { coordinate, code }],
                    };
                    assert_eq!(
                        CompactMsg(msg.clone()).encode().ok(),
                        reference::CompactMsg(msg).encode().ok()
                    );
                }
            }
        }
    }
    for entries in [
        vec![],
        vec![
            Entry {
                coordinate: 0,
                code: 2,
            },
            Entry {
                coordinate: 0,
                code: 3,
            },
        ],
        vec![
            Entry {
                coordinate: 0,
                code: 5
            };
            274
        ],
    ] {
        let msg = ProtMsg {
            instance: InstanceId::new(0, None, 0),
            round: 2,
            entries,
        };
        assert_eq!(
            CompactMsg(msg.clone()).encode().ok(),
            reference::CompactMsg(msg).encode().ok()
        );
    }
}
