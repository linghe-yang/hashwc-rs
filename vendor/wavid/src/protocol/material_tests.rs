use super::*;
use crate::{CompletionMode, Descriptor, Kind, ProtMsg, Retrieval, State, CHUNK_BYTES};
use types::{InstanceId, Weight, WeightedMembership};

fn fixture(bytes: usize) -> (State, Vec<u8>, crate::Prepared, VerifiedMaterial) {
    let membership = WeightedMembership::new(vec![Weight::from(3); 4], Weight::from(4)).unwrap();
    let instance = InstanceId::new(7, Some(0), 0);
    let data: Vec<_> = (0..bytes).map(|i| (i * 17 + 5) as u8).collect();
    let codec = Arc::new(
        Codec::with_params(
            &membership,
            instance,
            [9; 32],
            bytes,
            crate::CodingParams { block_bytes: 32 },
        )
        .unwrap(),
    );
    let prepared = codec.prepare(&data).unwrap();
    let material = VerifiedMaterial::new(codec, prepared.root);
    let mut state = State::new(
        membership,
        3,
        instance,
        [9; 32],
        Descriptor {
            coding: crate::CodingParams { block_bytes: 32 },
            file_bytes: bytes,
            root: Some(prepared.root),
            retrievers: vec![2, 3],
            completion: CompletionMode::External,
        },
    )
    .unwrap();
    state.attach_material(material.clone()).unwrap();
    (state, data, prepared, material)
}
fn start(state: &mut State, root: Hash) {
    state.accept_completion(root).unwrap();
    state.retrieve().unwrap();
}
fn chunk(state: &mut State, owner: usize, raw: &[u8], i: usize) {
    state.receive(
        owner,
        ProtMsg {
            instance: state.instance,
            kind: Kind::Data {
                index: i as u32,
                bytes: raw[i * CHUNK_BYTES..raw.len().min((i + 1) * CHUNK_BYTES)].to_vec(),
            },
        },
    );
}
fn raw(state: &State, p: &crate::Prepared) -> Vec<Vec<u8>> {
    (0..4)
        .map(|i| state.codec.encode_bundle(i, &p.bundles[i]).unwrap())
        .collect()
}
fn file(state: &State) -> &ValidatedFile {
    let Some(Retrieval::File(f)) = &state.result else {
        panic!("missing file")
    };
    f
}
#[test]
fn certificate_first_preserves_completion_gate_and_late_holder_service() {
    let (mut state, data, p, material) = fixture(4117);
    assert!(material.verify_parts(data.chunks(17)).unwrap().is_some());
    state.poll_material().unwrap();
    assert!(state.result.is_none() && state.completed_root.is_none());
    state.retrieve().unwrap();
    state.poll_material().unwrap();
    assert!(state.result.is_none() && state.outgoing.is_empty());
    state.accept_completion(p.root).unwrap();
    assert_eq!(file(&state).as_ref(), data);
    assert_eq!(
        state
            .outgoing
            .iter()
            .filter(|a| matches!(a.message.kind, Kind::Request(_)))
            .count(),
        4
    );
    let before = material.stats().unwrap();
    // Local recovery completion does not replace a real holder receipt or service.
    let packets = raw(&state, &p);
    state.receive(
        2,
        ProtMsg {
            instance: state.instance,
            kind: Kind::Request(p.root),
        },
    );
    for (i, bytes) in packets[3].chunks(CHUNK_BYTES).enumerate() {
        state.receive(
            0,
            ProtMsg {
                instance: state.instance,
                kind: Kind::Init {
                    index: i as u32,
                    bytes: bytes.to_vec(),
                },
            },
        );
    }
    assert_eq!(state.stored_root, Some(p.root));
    assert!(state
        .outgoing
        .iter()
        .any(|a| a.recipient == 2 && matches!(a.message.kind, Kind::Data { .. })));
    for owner in [1, 2] {
        for i in 0..packets[owner].len().div_ceil(CHUNK_BYTES) {
            chunk(&mut state, owner, &packets[owner], i);
        }
    }
    assert_eq!(material.stats().unwrap(), before);
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
fn partial_stripes_then_candidate_reuse_and_invalid_candidate_cannot_poison() {
    for bad_first in [false, true] {
        let (mut state, data, p, material) = fixture(131109);
        start(&mut state, p.root);
        let packets = raw(&state, &p);
        for owner in [1, 2] {
            for i in 0..2 {
                chunk(&mut state, owner, &packets[owner], i);
            }
        }
        let first = material.stats().unwrap();
        assert!(first.decoded_stripes > 0 && first.decoded_stripes < state.codec.q);
        assert!(material.file().unwrap().is_none());
        if bad_first {
            let mut wrong = data.clone();
            wrong[73] ^= 1;
            assert!(material.verify_parts(wrong.chunks(37)).unwrap().is_none());
            assert!(material.file().unwrap().is_none());
            assert_eq!(
                material.stats().unwrap().decoded_stripes,
                first.decoded_stripes
            );
        }
        let before = material.stats().unwrap();
        let verified = material.verify_parts(data.chunks(19)).unwrap().unwrap();
        let after = material.stats().unwrap();
        assert_eq!(
            after.reused_stripes - before.reused_stripes,
            first.decoded_stripes
        );
        assert_eq!(
            after.encoded_stripes - before.encoded_stripes,
            state.codec.q - first.decoded_stripes
        );
        state.poll_material().unwrap();
        assert_eq!(file(&state).as_ref(), data);
        assert_eq!(verified.as_ref(), data);
        for owner in [2, 1] {
            for i in (0..packets[owner].len().div_ceil(CHUNK_BYTES)).rev() {
                chunk(&mut state, owner, &packets[owner], i);
            }
        }
        assert_eq!(material.stats().unwrap(), after);
        let proof = verified.open_source(state.codec.k - 1).unwrap();
        assert!(state.codec.verify_source(p.root, &proof));
    }
}
#[test]
fn retrieval_first_reuses_full_file_and_rejects_wrong_length_and_bytes() {
    let (mut state, data, p, material) = fixture(4117);
    start(&mut state, p.root);
    let packets = raw(&state, &p);
    for owner in [1, 2] {
        for i in 0..packets[owner].len().div_ceil(CHUNK_BYTES) {
            chunk(&mut state, owner, &packets[owner], i);
        }
    }
    assert_eq!(file(&state).as_ref(), data);
    let before = material.stats().unwrap();
    assert_eq!(before.decoded_stripes, state.codec.q);
    assert_eq!(before.encoded_stripes, 0);
    assert!(material.verify_parts(data.chunks(7)).unwrap().is_some());
    let mut wrong = data.clone();
    wrong[73] ^= 1;
    assert!(material.verify_parts([wrong.as_slice()]).unwrap().is_none());
    assert!(material
        .verify_parts([&data[..data.len() - 1]])
        .unwrap()
        .is_none());
    assert_eq!(material.stats().unwrap().encoded_stripes, 0);
    assert_eq!(material.file().unwrap().unwrap().as_ref(), data);
}
#[test]
fn local_attachment_rejects_wrong_root_context_and_late_or_selective_mode() {
    let (state, data, p, _) = fixture(4117);
    for (root, public_id) in [([5; 32], [9; 32]), (p.root, [8; 32])] {
        let c = Arc::new(
            Codec::with_params(
                &state.membership,
                state.instance,
                public_id,
                data.len(),
                state.codec.parameters(),
            )
            .unwrap(),
        );
        let bad = VerifiedMaterial::new(c, root);
        assert!(!bad.matches(&state.codec, p.root));
        let mut fresh = State::new(
            state.membership.clone(),
            3,
            state.instance,
            [9; 32],
            state.descriptor.clone(),
        )
        .unwrap();
        assert!(fresh.attach_material(bad).is_err());
        assert!(fresh.material.is_none());
    }
    let mut late = State::new(
        state.membership.clone(),
        3,
        state.instance,
        [9; 32],
        state.descriptor.clone(),
    )
    .unwrap();
    start(&mut late, p.root);
    assert!(late
        .attach_material(VerifiedMaterial::new(Arc::new(state.codec.clone()), p.root))
        .is_err());
    let mut selective = State::new(
        state.membership.clone(),
        3,
        state.instance,
        [9; 32],
        state.descriptor.clone(),
    )
    .unwrap()
    .with_selection_budget(Some(1))
    .unwrap();
    assert!(selective
        .attach_material(VerifiedMaterial::new(Arc::new(state.codec.clone()), p.root))
        .is_err());
}
#[test]
fn concurrent_retrieval_and_success_share_one_stripe_computation() {
    for _ in 0..6 {
        let (mut state, data, p, material) = fixture(16421);
        start(&mut state, p.root);
        let packets = raw(&state, &p);
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let b = barrier.clone();
        let verifier = material.clone();
        let expected = data.clone();
        let t = std::thread::spawn(move || {
            b.wait();
            verifier.verify_parts(expected.chunks(23)).unwrap().unwrap()
        });
        barrier.wait();
        for owner in [1, 2] {
            for i in 0..packets[owner].len().div_ceil(CHUNK_BYTES) {
                chunk(&mut state, owner, &packets[owner], i);
            }
        }
        let verified = t.join().unwrap();
        state.poll_material().unwrap();
        assert_eq!(file(&state).as_ref(), data);
        assert_eq!(verified.as_ref(), data);
        let stats = material.stats().unwrap();
        assert_eq!(stats.decoded_stripes + stats.encoded_stripes, state.codec.q);
        assert_eq!(stats.rejected_candidates, 0);
    }
}

#[test]
fn shared_recovery_keeps_coding_and_padding_faults_publicly_verifiable() {
    for padding in [false, true] {
        let (mut state, data, p, _) = fixture(4117);
        let mut rows = p.rows;
        if padding {
            let z = state.codec.q - 1;
            let mut source = state.codec.source_stripe(&data, z);
            source[data.len() % (state.codec.k * 32)] = 1;
            rows[z] = state
                .codec
                .encode_stripe(&source)
                .unwrap()
                .chunks_exact(32)
                .map(|x| x.to_vec())
                .collect();
        } else {
            rows[0][state.codec.m - 1][0] ^= 1;
        }
        let bad = state.codec.commit_rows(rows).unwrap();
        // Test fixture substitutes the entire dealer commitment before retrieval.
        state.descriptor.root = Some(bad.root);
        let material = VerifiedMaterial::new(Arc::new(state.codec.clone()), bad.root);
        state.material = Some(material.clone());
        start(&mut state, bad.root);
        let packets = raw(&state, &bad);
        for owner in [1, 2] {
            for i in 0..packets[owner].len().div_ceil(CHUNK_BYTES) {
                chunk(&mut state, owner, &packets[owner], i);
            }
        }
        let Some(Retrieval::Invalid(fault)) = &state.result else {
            panic!("fault missed")
        };
        assert!(state.codec.verify_fault(bad.root, fault));
        assert!(material.file().unwrap().is_none());
        assert!(material.verify_parts(data.chunks(31)).unwrap().is_none());
        assert!(material.file().unwrap().is_none());
    }
}
