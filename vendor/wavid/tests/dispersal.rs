use types::{InstanceId, Weight, WeightedMembership};
use wavid::{Codec, CodingParams, CompletionMode, Descriptor, State};

#[test]
fn single_pass_preserves_wire_packets_proofs_and_rejects_wrong_bindings() {
    // GF8 and GF16; empty, unaligned and multi-stripe source files.
    for (n, bytes, block_bytes) in [(4, 0, 32), (4, 401, 34), (4, 4097, 256), (90, 6001, 34)] {
        let membership =
            WeightedMembership::new(vec![Weight::from(3); n], Weight::from(n as u64)).unwrap();
        let instance = InstanceId::new(5, Some(0), 7);
        let descriptor = Descriptor {
            coding: CodingParams { block_bytes },
            file_bytes: bytes,
            root: None,
            retrievers: vec![],
            completion: CompletionMode::External,
        };
        let codec =
            Codec::with_params(&membership, instance, [5; 32], bytes, descriptor.coding).unwrap();
        let data: Vec<_> = (0..bytes).map(|i| (i * 19) as u8).collect();
        let selected = [0, codec.k - 1, codec.q * codec.k - 1]
            .into_iter()
            .collect();
        let prep = codec.prepare_dispersal(data.clone(), &selected).unwrap();
        let eager = codec.prepare(&data).unwrap();
        assert_eq!(prep.file().root(), eager.root);
        assert_eq!(prep.file().as_ref(), data.as_slice());
        for &block in &selected {
            let proof = prep.open_source(block).unwrap();
            assert!(codec.verify_source(eager.root, &proof));
            assert_eq!(
                bincode::serialize(&proof).unwrap(),
                bincode::serialize(&codec.source_opening(&eager, block).unwrap()).unwrap()
            );
        }
        assert!(prep.open_source(codec.q * codec.k).is_err());
        assert!(codec
            .prepare_dispersal(data.clone(), &[codec.q * codec.k].into_iter().collect())
            .is_err());
        let make = |id, instance, public_id, descriptor| {
            State::new(membership.clone(), id, instance, public_id, descriptor).unwrap()
        };
        let mut old = make(0, instance, [5; 32], descriptor.clone());
        old.disperse(&data).unwrap();
        let mut new = make(0, instance, [5; 32], descriptor.clone());
        new.disperse_cached(prep.clone()).unwrap();
        assert_eq!(old.outgoing.len(), new.outgoing.len());
        for (a, b) in old.outgoing.iter().zip(&new.outgoing) {
            assert_eq!(a.recipient, b.recipient);
            assert_eq!(a.message, b.message);
        }
        assert!(new.disperse_cached(prep.clone()).is_err());
        let mut nondealer = make(1, instance, [5; 32], descriptor.clone());
        assert!(nondealer.disperse_cached(prep.clone()).is_err());
        for other in [
            InstanceId::new(6, Some(0), 7),
            InstanceId::new(5, Some(0), 8),
        ] {
            let mut st = make(0, other, [5; 32], descriptor.clone());
            assert!(st.disperse_cached(prep.clone()).is_err());
            assert!(st.outgoing.is_empty());
        }
        let mut st = make(0, instance, [6; 32], descriptor.clone());
        assert!(st.disperse_cached(prep.clone()).is_err());
        let mut wrong = descriptor.clone();
        wrong.root = Some([0; 32]);
        let mut st = make(0, instance, [5; 32], wrong);
        assert!(st.disperse_cached(prep.clone()).is_err());
        let mut wrong = descriptor.clone();
        wrong.coding.block_bytes = 128;
        let mut st = make(0, instance, [5; 32], wrong);
        assert!(st.disperse_cached(prep.clone()).is_err());
        let mut wrong = descriptor.clone();
        wrong.file_bytes += 1;
        let mut st = make(0, instance, [5; 32], wrong);
        assert!(st.disperse_cached(prep).is_err());
    }
}
