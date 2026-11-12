use super::super::{ack_mac, decode_value, frame_mac, mac_prefix, Frame};
use super::*;
use std::{hint::black_box, time::Instant};

fn reference(raw: &[u8]) -> Option<Frame> {
    // The old network receiver checks the outer u32 length before decoding.
    if raw.is_empty() || raw.len() > MAX_FRAME_BYTES {
        return None;
    }
    decode_value(raw).ok()
}
fn check(raw: &[u8]) {
    match (reference(raw), FrameRef::parse(raw)) {
        (None, Err(_)) => {}
        (Some(old), Ok(new)) => {
            assert_eq!(&old.context, new.context);
            assert_eq!(old.sender, new.sender);
            assert_eq!(old.recipient, new.recipient);
            assert_eq!(old.sequence, new.sequence);
            assert_eq!(old.payload, new.payload);
            assert_eq!(&old.mac, new.mac);
        }
        _ => panic!(
            "borrowed and legacy acceptance differ: len={}, header={:?}, legacy={}",
            raw.len(),
            &raw[..raw.len().min(64)],
            reference(raw).is_some()
        ),
    }
}
fn fixture(size: usize, sequence: u64) -> Frame {
    let mut f = Frame {
        context: [9; 32],
        sender: 0,
        recipient: 1,
        sequence,
        payload: (0..size).map(|i| (i % 251) as u8).collect(),
        mac: [0; 32],
    };
    f.mac = frame_mac(&f, &[7; 32]);
    f
}
#[test]
fn borrowed_envelope_matches_strict_bincode_and_authentication() {
    for size in [0, 1, 7, 64, 4096, 65536, MAX_FRAME_BYTES - 96] {
        for sequence in [0, 1, u64::MAX] {
            let f = fixture(size, sequence);
            let raw = bincode::serialize(&f).unwrap();
            check(&raw);
            let view = FrameRef::parse(&raw).unwrap();
            assert!(view.verify(&[7; 32]));
            assert!(!view.verify(&[8; 32]));
            assert_eq!(view.ack(&[7; 32]), ack_mac(&f, &[7; 32]));
            assert_eq!(view.payload.as_ptr(), raw[64..].as_ptr());
            for field in [0, 31, 32, 39, 40, 47, 48, 55, raw.len() - 1] {
                let mut altered = raw.clone();
                altered[field] ^= 1;
                check(&altered);
                assert!(!FrameRef::parse(&altered).unwrap().verify(&[7; 32]));
            }
            if size > 0 {
                let mut altered = raw.clone();
                altered[64] ^= 1;
                assert!(!FrameRef::parse(&altered).unwrap().verify(&[7; 32]));
            }
        }
    }
}
#[test]
fn malformed_lengths_trailing_truncation_and_random_bytes_match_reference() {
    let mut checked = 0;
    for size in [0, 1, 8, 33, 512] {
        let raw = bincode::serialize(&fixture(size, 1)).unwrap();
        for end in 0..raw.len() {
            check(&raw[..end]);
            checked += 1;
        }
        for length in [
            0,
            1,
            8,
            33,
            512,
            MAX_FRAME_BYTES as u64,
            u32::MAX as u64,
            u64::MAX,
        ] {
            let mut bad = raw.clone();
            bad[56..64].copy_from_slice(&length.to_le_bytes());
            check(&bad);
            checked += 1;
        }
        for pos in 0..raw.len() {
            let mut altered = raw.clone();
            altered[pos] ^= 0x80;
            check(&altered);
            checked += 1;
        }
        let mut extra = raw;
        extra.push(0);
        check(&extra);
        checked += 1;
    }
    let mut seed = 20261023u64;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for _ in 0..20_000 {
        let size = (next() % 513) as usize;
        let raw: Vec<_> = (0..size).map(|_| next() as u8).collect();
        check(&raw);
        checked += 1;
    }
    let mut too_large = bincode::serialize(&fixture(MAX_FRAME_BYTES - 95, 1)).unwrap();
    check(&too_large);
    too_large[56..64].copy_from_slice(&u64::MAX.to_le_bytes());
    check(&too_large);
    eprintln!("frame differential: {} acceptance comparisons", checked + 2);
}
#[test]
fn machine_word_boundaries_and_ack_domain_match() {
    for sender in [0, 1, usize::MAX] {
        for recipient in [0, 1, usize::MAX] {
            let mut f = fixture(3, u64::MAX);
            f.sender = sender;
            f.recipient = recipient;
            f.mac = frame_mac(&f, &[7; 32]);
            let raw = bincode::serialize(&f).unwrap();
            check(&raw);
            let view = FrameRef::parse(&raw).unwrap();
            assert!(view.verify(&[7; 32]));
            assert_eq!(view.ack(&[7; 32]), ack_mac(&f, &[7; 32]));
        }
    }
}

#[test]
#[ignore = "release microbenchmark; not a correctness test"]
fn frame_microbenchmark() {
    println!("FRAME_BENCH,payload_bytes,old_parse_ns,new_parse_ns,old_verify_ns,new_verify_ns,old_ack_ns,new_ack_ns");
    for size in [7, 64, 4096, 32768, 262144, MAX_FRAME_BYTES - 256] {
        let f = fixture(size, 1);
        let raw = bincode::serialize(&f).unwrap();
        let view = FrameRef::parse(&raw).unwrap();
        let iterations = (1_048_576 / raw.len()).clamp(8, 2000);
        let mut samples: [Vec<f64>; 6] = Default::default();
        for pass in 0..10 {
            let order: Vec<_> = if pass % 2 == 0 {
                (0..6).collect()
            } else {
                (0..6).rev().collect()
            };
            for k in order {
                let start = Instant::now();
                for _ in 0..iterations {
                    match k {
                        0 => {
                            black_box(reference(black_box(&raw)).unwrap());
                        }
                        1 => {
                            black_box(FrameRef::parse(black_box(&raw)).unwrap());
                        }
                        2 => {
                            black_box(verify_mac_parts(
                                &[&mac_prefix(black_box(&f)), &f.payload],
                                &[7; 32],
                                &f.mac,
                            ));
                        }
                        3 => {
                            black_box(black_box(&view).verify(&[7; 32]));
                        }
                        4 => {
                            black_box(ack_mac(black_box(&f), &[7; 32]));
                        }
                        _ => {
                            black_box(black_box(&view).ack(&[7; 32]));
                        }
                    }
                }
                if pass > 0 {
                    samples[k].push(start.elapsed().as_nanos() as f64 / iterations as f64);
                }
            }
        }
        for s in &mut samples {
            s.sort_by(f64::total_cmp);
        }
        println!(
            "FRAME_BENCH,{size},{:.1},{:.1},{:.1},{:.1},{:.1},{:.1}",
            samples[0][4],
            samples[1][4],
            samples[2][4],
            samples[3][4],
            samples[4][4],
            samples[5][4]
        );
    }
}
