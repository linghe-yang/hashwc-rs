use sdc_types::{InstanceId, WeightedMembership};
use wavid::{Codec, CodingParams};
use wiawvss::{
    Context, Limits, Opening, Public, Setup, ax,
    blocksize::{BlockSize, Model},
    certified::{self, Receipt},
};

fn setup() -> Setup {
    Setup::new_clean(
        types::Policy::new(
            vec![1u8.into(), 2u8.into(), 3u8.into(), 6u8.into()],
            4u8.into(),
        )
        .unwrap(),
        Limits::default(),
    )
    .unwrap()
}
fn codec(s: &Setup, b: usize, pvr: bool) -> Codec {
    let p = s.circuit().policy();
    let members = WeightedMembership::new(
        p.weights()
            .iter()
            .map(|w| w.to_string().parse().unwrap())
            .collect(),
        p.threshold().to_string().parse().unwrap(),
    )
    .unwrap();
    Codec::with_params(
        &members,
        InstanceId::new(7, Some(0), 0),
        [13; 32],
        if pvr {
            Public::encoded_len(s)
        } else {
            wiawvss::compact::Public::encoded_len(s)
        },
        CodingParams { block_bytes: b },
    )
    .unwrap()
}
// Independently serialize the transport envelope shape, length prefix and ACK.
fn frame_bytes<T: serde::Serialize>(value: &T) -> usize {
    let payload = bincode::serialize(value).unwrap();
    bincode::serialized_size(&([0u8; 32], 0usize, 1usize, 0u64, payload, [0u8; 32])).unwrap()
        as usize
        + 4
        + 32
}
fn private_bytes(raw: Vec<u8>) -> usize {
    let packet = network::Packet {
        epoch: 7,
        dealer: 0,
        kind: 0,
        payload: raw,
    };
    let sealed = network::Sealed {
        nonce: [0; 12],
        ciphertext: vec![0; bincode::serialized_size(&packet).unwrap() as usize + 16],
    };
    frame_bytes(&sealed)
}

#[test]
fn ledger_matches_real_bundle_message_and_receipt_serializations() {
    let s = setup();
    let context = Context::new(
        &s,
        types::Instance {
            session: [7; 32],
            epoch: 7,
            dealer: 0,
        },
        vec![],
    )
    .unwrap();
    let (public, shares) = ax::generate(
        &s,
        &context,
        &Opening {
            message: [0; 32],
            randomness: [19; 32],
        },
    )
    .unwrap();
    let reference = codec(&s, 32, true);
    let loads = vec![1, 2, 3, 4];
    let model = Model::new(&s, &reference, loads.clone(), true).unwrap();
    for b in [
        32,
        34,
        66,
        128,
        510,
        1024,
        4096,
        model.select().unwrap().chosen.block_bytes,
    ] {
        let c = codec(&s, b, true);
        let prepared = c.prepare(&public.encode()).unwrap();
        let mut init = 0u128;
        let mut retrieval = 0u128;
        let mut receipts = 0u128;
        for (i, share) in shares.iter().enumerate() {
            let raw = c.encode_bundle(i, &prepared.bundles[i]).unwrap();
            assert_eq!(raw.len(), c.bundle_bytes(i));
            let wire: usize = raw
                .chunks(wavid::CHUNK_BYTES)
                .enumerate()
                .map(|(j, bytes)| {
                    let init = wavid::ProtMsg {
                        instance: InstanceId::new(7, Some(0), 0),
                        kind: wavid::Kind::Init {
                            index: j as u32,
                            bytes: bytes.to_vec(),
                        },
                    };
                    let data = wavid::ProtMsg {
                        instance: init.instance,
                        kind: wavid::Kind::Data {
                            index: j as u32,
                            bytes: bytes.to_vec(),
                        },
                    };
                    assert_eq!(frame_bytes(&init), frame_bytes(&data));
                    frame_bytes(&init)
                })
                .sum();
            init += 3 * wire as u128;
            retrieval += (10 - loads[i]) as u128 * wire as u128;
            let receipt = Receipt::new(&s, &c, &prepared, share).unwrap();
            receipts += 3 * private_bytes(receipt.encode()) as u128;
        }
        let candidate = model.evaluate(b).unwrap();
        assert_eq!(candidate.initial_bundle_bytes, init, "b={b}");
        assert_eq!(candidate.retrieval_bundle_bytes, retrieval, "b={b}");
        assert_eq!(candidate.private_receipt_bytes, receipts, "b={b}");
        assert_eq!(candidate.variable_ledger_bytes, init + retrieval + receipts);
    }
}

#[test]
fn exhaustively_minimizes_all_2033_candidates_for_both_protocols() {
    let s = setup();
    for pvr in [false, true] {
        let base = codec(&s, 32, pvr);
        let model = Model::new(&s, &base, vec![4; 4], pvr).unwrap();
        let mut request = BlockSize::default();
        let selected = request.select(&model).unwrap();
        assert_eq!(selected.candidates, 2033);
        let mut best = None;
        for b in (32..=4096).step_by(2) {
            let c = codec(&s, b, pvr);
            let x = model.evaluate(b).unwrap();
            // A second cost calculation from Codec geometry verifies the full
            // grid (including non-powers-of-two padding discontinuities).
            let network: usize = (0..4)
                .map(|i| {
                    let raw = c.bundle_bytes(i);
                    15 * (raw + raw.div_ceil(wavid::CHUNK_BYTES) * 173)
                })
                .sum();
            assert_eq!(
                x.initial_bundle_bytes + x.retrieval_bundle_bytes,
                network as u128
            );
            if pvr {
                assert!(x.fault_frame_bound >= certified::max_module_evidence_bytes(&s, &c) + 61);
            }
            if x.feasible {
                let pair = (x.variable_ledger_bytes, b);
                if best.is_none_or(|old| pair < old) {
                    best = Some(pair);
                }
            }
        }
        assert_eq!(
            best,
            Some((
                selected.chosen.variable_ledger_bytes,
                selected.chosen.block_bytes
            ))
        );
        assert_eq!(request.bytes(), Some(selected.chosen.block_bytes));
        assert_eq!(
            serde_json::to_string(&request).unwrap(),
            "\"min-communication-v1\""
        );
        // Reference codec's block geometry is not an input to the decision.
        let other = codec(&s, 1024, pvr);
        assert_eq!(
            Model::new(&s, &other, vec![4; 4], pvr)
                .unwrap()
                .select()
                .unwrap()
                .chosen
                .block_bytes,
            selected.chosen.block_bytes
        );
    }
}
