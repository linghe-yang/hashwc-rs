use types::{InstanceId, Weight, WeightedMembership};
use wavid::{Codec, CompletionMode, Descriptor, State};
#[test]
fn compact_wire_matches_streaming_prepare_and_rejects_tampering() {
    for (n, b) in [(4, 32), (64, 32), (90, 32), (4, 256), (90, 128)] {
        let membership =
            WeightedMembership::new(vec![Weight::from(3); n], Weight::from(n as u64)).unwrap();
        let instance = InstanceId::new(1, Some(0), 0);
        let data = vec![27; 4097];
        let codec = Codec::with_params(
            &membership,
            instance,
            [1; 32],
            data.len(),
            wavid::CodingParams { block_bytes: b },
        )
        .unwrap();
        let prepared = codec.prepare(&data).unwrap();
        let mut state = State::new(
            membership,
            0,
            instance,
            [1; 32],
            Descriptor {
                coding: wavid::CodingParams { block_bytes: b },
                file_bytes: data.len(),
                root: Some(prepared.root),
                retrievers: vec![],
                completion: CompletionMode::Storage,
            },
        )
        .unwrap();
        state.disperse(&data).unwrap();
        let mut total = 0;
        let mut legacy = 0;
        for owner in 0..n {
            let raw = codec
                .encode_bundle(owner, &prepared.bundles[owner])
                .unwrap();
            assert_eq!(raw.len(), codec.bundle_bytes(owner));
            total += raw.len();
            legacy += bincode::serialize(&prepared.bundles[owner]).unwrap().len();
            let opened = codec.decode_bundle(owner, &raw).unwrap();
            assert_eq!(
                codec.verify_bundle(owner, &opened, Some(prepared.root)),
                Some(prepared.root)
            );
            let network: Vec<u8> = state
                .outgoing
                .iter()
                .filter(|a| a.recipient == owner)
                .flat_map(|a| match &a.message.kind {
                    wavid::Kind::Init { bytes, .. } => bytes.clone(),
                    _ => vec![],
                })
                .collect();
            assert_eq!(raw, network);
            let mut bad = raw.clone();
            bad[0] = 1;
            assert!(codec.decode_bundle(owner, &bad).is_none());
            let mut bad = raw.clone();
            *bad.last_mut().unwrap() ^= 1;
            assert!(codec.decode_bundle(owner, &bad).is_none());
            assert!(codec.decode_bundle(owner, &raw[..raw.len() - 1]).is_none());
        }
        assert!(total < legacy, "compact={total}, legacy={legacy}");
        println!("n={n} compact_bytes={total} legacy_bytes={legacy}");
    }
}
