use super::*;
use crate::{CompletionMode, Descriptor, Kind, ProtMsg, Retrieval, State, StorageFault};
use types::{InstanceId, Weight, WeightedMembership};

fn setup() -> (State, Vec<u8>, crate::Prepared) {
    setup_with(4, 32, 131109)
}
fn setup_with(
    n: usize,
    block_bytes: usize,
    file_bytes: usize,
) -> (State, Vec<u8>, crate::Prepared) {
    let membership =
        WeightedMembership::new(vec![Weight::from(3); n], Weight::from(n as u64)).unwrap();
    let data: Vec<_> = (0..file_bytes).map(|i| (i * 17 + 5) as u8).collect();
    let instance = InstanceId::new(0, Some(0), 8);
    let coding = crate::CodingParams { block_bytes };
    let codec = Codec::with_params(&membership, instance, [9; 32], data.len(), coding).unwrap();
    let prepared = codec.prepare(&data).unwrap();
    let mut state = State::new(
        membership,
        n - 1,
        instance,
        [9; 32],
        Descriptor {
            coding,
            file_bytes: data.len(),
            root: Some(prepared.root),
            retrievers: vec![n - 1],
            completion: CompletionMode::External,
        },
    )
    .unwrap();
    state.accept_completion(prepared.root).unwrap();
    state.retrieve().unwrap();
    (state, data, prepared)
}
fn chunk(state: &mut State, owner: usize, raw: &[u8], index: usize) {
    state.receive(
        owner,
        ProtMsg {
            instance: state.instance,
            kind: Kind::Data {
                index: index as u32,
                bytes: raw[index * CHUNK_BYTES..raw.len().min((index + 1) * CHUNK_BYTES)].to_vec(),
            },
        },
    );
}
fn packets(state: &State, p: &crate::Prepared) -> Vec<Vec<u8>> {
    (0..4)
        .map(|i| state.codec.encode_bundle(i, &p.bundles[i]).unwrap())
        .collect()
}
#[test]
fn recovers_before_complete_packets_and_preserves_proofs_after_reordered_tail() {
    let (mut state, data, p) = setup();
    let raw = packets(&state, &p);
    // The directory itself crosses a chunk boundary in this fixture.
    assert!(state.codec.directory_bytes() > CHUNK_BYTES);
    for owner in [1, 2] {
        for i in 0..2 {
            chunk(&mut state, owner, &raw[owner], i);
        }
    }
    let recovery = state.recovery.as_ref().unwrap();
    let done = recovery.done.iter().filter(|d| **d).count();
    assert!(done > 0 && done < state.codec.q);
    assert!(state.result.is_none());
    assert_eq!(
        &recovery.data[..done * state.codec.k * 32],
        &data[..done * state.codec.k * 32]
    );
    assert!(state.rows[..done].iter().all(|row| row.is_empty()));
    assert!(state.data_slots.values().all(|s| s.parts.len() <= 1));
    // Replays cannot recreate coordinates or overwrite partially consumed chunks.
    for owner in [1, 2] {
        for i in 0..2 {
            chunk(&mut state, owner, &raw[owner], i);
        }
    }
    assert_eq!(
        state
            .recovery
            .as_ref()
            .unwrap()
            .done
            .iter()
            .filter(|d| **d)
            .count(),
        done
    );
    for owner in [2, 1] {
        for i in (2..raw[owner].len().div_ceil(CHUNK_BYTES)).rev() {
            chunk(&mut state, owner, &raw[owner], i);
        }
    }
    let Some(Retrieval::File(file)) = &state.result else {
        panic!("missing validated file")
    };
    assert_eq!(file.as_ref(), data);
    assert!(state
        .codec
        .verify_source(p.root, &file.open_source(0).unwrap()));
    assert!(state.data_slots.is_empty() && state.recovery.is_none());
    assert_eq!(
        state
            .events
            .iter()
            .filter(|e| matches!(e, crate::Event::Result { .. }))
            .count(),
        1
    );
}
#[test]
fn coding_fault_is_reported_with_original_paths_before_packet_tail_arrives() {
    let (mut state, _, p) = setup();
    let mut rows = p.rows;
    rows[0][state.codec.m - 1][0] ^= 1;
    let bad = state.codec.commit_rows(rows).unwrap();
    state.descriptor.root = Some(bad.root);
    state.completed_root = Some(bad.root);
    let raw = packets(&state, &bad);
    for owner in [1, 2] {
        for i in 0..2 {
            chunk(&mut state, owner, &raw[owner], i);
        }
    }
    let Some(Retrieval::Invalid(fault @ StorageFault::Coding(w))) = &state.result else {
        panic!("missing early coding fault")
    };
    assert_eq!(w.stripe, 0);
    assert!(state.codec.verify_fault(bad.root, fault));
    for fragment in &w.fragments {
        assert!(crypto::weighted_merkle::verify(
            state.codec.stripe_context(0),
            w.root,
            state.codec.m,
            fragment.index,
            &fragment.data,
            &fragment.proof
        ));
    }
}
#[test]
fn successful_prefix_does_not_hide_invalid_padding_in_last_stripe() {
    let (mut state, data, p) = setup();
    let mut rows = p.rows;
    let z = state.codec.q - 1;
    let mut source = state.codec.source_stripe(&data, z);
    source[data.len() % (state.codec.k * 32)] = 1;
    rows[z] = state
        .codec
        .encode_stripe(&source)
        .unwrap()
        .chunks_exact(32)
        .map(|b| b.to_vec())
        .collect();
    let bad = state.codec.commit_rows(rows).unwrap();
    state.descriptor.root = Some(bad.root);
    state.completed_root = Some(bad.root);
    let raw = packets(&state, &bad);
    for owner in [1, 2] {
        for i in 0..2 {
            chunk(&mut state, owner, &raw[owner], i);
        }
    }
    assert!(state.recovery.as_ref().unwrap().done[0]);
    assert!(state.result.is_none());
    for owner in [1, 2] {
        for i in 2..raw[owner].len().div_ceil(CHUNK_BYTES) {
            chunk(&mut state, owner, &raw[owner], i);
        }
    }
    let Some(Retrieval::Invalid(fault @ StorageFault::Padding(_))) = &state.result else {
        panic!("padding was not checked")
    };
    assert!(state.codec.verify_fault(bad.root, fault));
}
#[test]
fn bad_sender_suffix_does_not_poison_validated_prefix_or_other_senders() {
    let (mut state, data, p) = setup();
    let mut raw = packets(&state, &p);
    // First three stripes have genuine proofs; stripe 3 has a corrupted path.
    let offset = state.codec.directory_bytes() + 4 * state.codec.stripe_bytes(0) - 1;
    raw[0][offset] ^= 1;
    for i in 0..2 {
        chunk(&mut state, 0, &raw[0], i);
    }
    assert!(state.data_slots[&0].closed);
    assert!(state.rows[0].len() > 0 && state.rows[3].is_empty());
    assert!(state.result.is_none()); // Invalid multiproof is not public evidence.
    for owner in [1, 2] {
        for i in 0..raw[owner].len().div_ceil(CHUNK_BYTES) {
            chunk(&mut state, owner, &raw[owner], i);
        }
    }
    assert!(matches!(&state.result, Some(Retrieval::File(f)) if f.as_ref()==data));
}
#[test]
fn malformed_directory_cannot_create_recovery_state() {
    for offset in [0, 1, 9] {
        // version, length, and a root byte
        let (mut state, _, p) = setup();
        let mut raw = state.codec.encode_bundle(0, &p.bundles[0]).unwrap();
        raw[offset] ^= 1;
        for i in 0..2 {
            chunk(&mut state, 0, &raw, i);
        }
        assert!(state.data_slots[&0].closed);
        assert!(state.recovery.is_none() && state.result.is_none());
    }
}
#[test]
fn chunk_cursor_handles_reordering_duplicates_and_cross_chunk_records() {
    let data: Vec<_> = (0..3 * CHUNK_BYTES + 7).map(|i| i as u8).collect();
    let mut stream = DataStream::new(data.len());
    for i in [2, 0, 0] {
        stream.add(
            i,
            data[i as usize * CHUNK_BYTES..(i as usize + 1) * CHUNK_BYTES].to_vec(),
        );
    }
    assert!(stream.take(CHUNK_BYTES + 1).is_none());
    assert_eq!(stream.take(31).unwrap(), data[..31]);
    stream.add(1, data[CHUNK_BYTES..2 * CHUNK_BYTES].to_vec());
    assert_eq!(
        stream.take(CHUNK_BYTES + 17).unwrap(),
        data[31..CHUNK_BYTES + 48]
    );
    stream.add(0, vec![99; CHUNK_BYTES]); // Already consumed: ignore.
    stream.add(1, vec![99; CHUNK_BYTES]); // Existing partially consumed chunk: first wins.
    stream.add(3, data[3 * CHUNK_BYTES..].to_vec());
    assert_eq!(
        stream.take(data.len() - CHUNK_BYTES - 48).unwrap(),
        data[CHUNK_BYTES + 48..]
    );
    assert!(stream.parts.is_empty() && stream.closed);
    let mut invalid = DataStream::new(10);
    invalid.add(u32::MAX, vec![0; 10]);
    assert!(invalid.closed && invalid.take(1).is_none());
}

#[test]
fn incremental_receiver_handles_gf16_and_empty_files() {
    for (n, block_bytes, len) in [(90, 128, 65573), (4, 128, 0)] {
        let (mut state, data, p) = setup_with(n, block_bytes, len);
        for owner in 1..n {
            let raw = state.codec.encode_bundle(owner, &p.bundles[owner]).unwrap();
            for i in 0..raw.len().div_ceil(CHUNK_BYTES) {
                chunk(&mut state, owner, &raw, i);
            }
        }
        let Some(Retrieval::File(file)) = &state.result else {
            panic!("missing file")
        };
        assert_eq!(file.as_ref(), data);
        assert!(state
            .codec
            .verify_source(p.root, &file.open_source(0).unwrap()));
    }
}
