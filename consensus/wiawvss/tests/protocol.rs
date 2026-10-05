use sdc_types::{InstanceId, Weight, WeightedMembership};
use types::{Instance, Policy};
use wavid::{Codec, Retrieval, StorageFault};
use wiawvss::{
    Context, Limits, Opening, Public, Setup, ax,
    certified::{self, Certificate, Evidence, Header, Receipt},
    terminal::{self, Terminal},
};
fn fixture() -> (Setup, Context, Codec, Opening) {
    let s = Setup::new(
        Policy::from_strings(&vec!["3".into(); 4], "4").unwrap(),
        Limits::default(),
    )
    .unwrap();
    let c = Context::new(
        &s,
        Instance {
            session: [3; 32],
            epoch: 1,
            dealer: 0,
        },
        vec![9],
    )
    .unwrap();
    let m = WeightedMembership::new(vec![Weight::from(3); 4], Weight::from(4)).unwrap();
    let codec = Codec::new(
        &m,
        InstanceId::new(1, Some(0), 0),
        [7; 32],
        Public::encoded_len(&s),
    )
    .unwrap();
    let mut message = [0; 32];
    message[31] = 17;
    (
        s,
        c,
        codec,
        Opening {
            message,
            randomness: [61; 32],
        },
    )
}
#[test]
fn header_is_constant_and_receipts_authenticate_both_digests_and_positions() {
    let (s, c, codec, o) = fixture();
    let (p, shares) = ax::generate(&s, &c, &o).unwrap();
    let prepared = codec.prepare(&p.encode()).unwrap();
    let h = Header::new(&s, &c, prepared.root);
    assert_eq!(h.encode().len(), 112);
    assert_eq!(Header::decode(&s, &c, &h.encode()).unwrap(), h);
    for share in shares {
        let r = Receipt::new(&s, &codec, &prepared, &share).unwrap();
        assert!(r.verify(&s, &c, &codec, &h, share.party).is_some());
        let raw = r.encode();
        assert!(Receipt::decode(&codec, &raw).is_ok());
        let mut bad = r.clone();
        bad.share[103] ^= 1;
        assert!(bad.verify(&s, &c, &codec, &h, share.party).is_none());
        let mut bad = r.clone();
        bad.fields[0].fragment.index = codec.k;
        assert!(bad.verify(&s, &c, &codec, &h, share.party).is_none());
        let mut bad = r.clone();
        bad.fields.pop();
        assert!(bad.verify(&s, &c, &codec, &h, share.party).is_none());
        let mut wrong = h.clone();
        wrong.root[0] ^= 1;
        assert!(r.verify(&s, &c, &codec, &wrong, share.party).is_none());
    }
    let mut bad = p.clone();
    bad.base.wires[2][0] ^= 1;
    let prep = codec.prepare(&bad.encode()).unwrap();
    let h = Header::new(&s, &c, prep.root);
    let (_, shares) = ax::generate(&s, &c, &o).unwrap();
    let r = Receipt::new(&s, &codec, &prep, &shares[0]).unwrap();
    assert!(r.verify(&s, &c, &codec, &h, 0).is_none());
}
#[test]
fn success_is_verified_from_header_only_and_binds_range_and_every_bulk_byte() {
    let (s, c, codec, o) = fixture();
    let (mut p, _) = ax::generate(&s, &c, &o).unwrap();
    let h = Header::new(&s, &c, codec.prepare(&p.encode()).unwrap().root);
    let cert = Certificate {
        header_id: h.id(),
        evidence: Evidence::Success(o.clone()),
    };
    assert!(certified::verify(&s, &c, &codec, &h, &cert, 8));
    assert!(!certified::verify(&s, &c, &codec, &h, &cert, 4));
    assert!(cert.encode().len() < 128);
    p.commitment[0] ^= 1;
    let h = Header::new(&s, &c, codec.prepare(&p.encode()).unwrap().root);
    let cert = Certificate {
        header_id: h.id(),
        evidence: Evidence::Success(o),
    };
    assert!(!certified::verify(&s, &c, &codec, &h, &cert, 8));
}
#[test]
fn semantic_certificates_need_only_authenticated_local_fields() {
    let (s, c, codec, o) = fixture();
    let (original, shares) = ax::generate(&s, &c, &o).unwrap();
    for kind in 0..5 {
        let mut p = original.clone();
        match kind {
            0 => p.base.true_token[0] ^= 1,
            1 => p.base.wires[2][0] ^= 1,
            2 => {
                for g in &mut p.base.gates {
                    g[0][0] ^= 1;
                    g[1][0] ^= 1;
                }
            }
            3 => p.commitment[0] ^= 1,
            _ => p.base.tag[0] ^= 1,
        };
        let prepared = codec.prepare(&p.encode()).unwrap();
        let h = Header::new(&s, &c, prepared.root);
        let t = terminal::recover_bounded(&s, &c, &p, &shares, 8).unwrap();
        assert!(!matches!(t, Terminal::Success(_)));
        let cert = certified::certify(&s, &codec, &h, &prepared, t).unwrap();
        assert!(certified::verify(&s, &c, &codec, &h, &cert, 8));
        let mut bad = cert.clone();
        if let Evidence::Semantic { fields, .. } = &mut bad.evidence {
            fields[0].fragment.data[0] ^= 1;
        }
        assert!(!certified::verify(&s, &c, &codec, &h, &bad, 8));
        let mut bad = cert.clone();
        if let Evidence::Semantic { fields, .. } = &mut bad.evidence {
            fields.clear();
        }
        assert!(!certified::verify(&s, &c, &codec, &h, &bad, 8));
    }
}
#[test]
fn out_of_range_candidate_requires_authenticated_output_token() {
    let (s, c, codec, o) = fixture();
    let (p, shares) = ax::generate(&s, &c, &o).unwrap();
    let prep = codec.prepare(&p.encode()).unwrap();
    let h = Header::new(&s, &c, prep.root);
    let t = terminal::recover_bounded(&s, &c, &p, &shares, 4).unwrap();
    assert!(matches!(t, Terminal::RootFault { .. }));
    let cert = certified::certify(&s, &codec, &h, &prep, t).unwrap();
    assert!(certified::verify(&s, &c, &codec, &h, &cert, 4));
    assert!(!certified::verify(&s, &c, &codec, &h, &cert, 8));
    let forged = certified::certify(
        &s,
        &codec,
        &h,
        &prep,
        Terminal::RootFault { token: [0; 32] },
    )
    .unwrap();
    assert!(!certified::verify(&s, &c, &codec, &h, &forged, 4));
}
#[test]
fn format_coding_padding_and_cross_instance_proofs() {
    let (s, c, codec, o) = fixture();
    let (p, _) = ax::generate(&s, &c, &o).unwrap();
    let mut raw = p.encode();
    raw[0] ^= 1;
    let prep = codec.prepare(&raw).unwrap();
    let h = Header::new(&s, &c, prep.root);
    let cert = Certificate {
        header_id: h.id(),
        evidence: Evidence::Format(certified::openings(&codec, &prep, &[(0, 72)]).unwrap()),
    };
    assert!(certified::verify(&s, &c, &codec, &h, &cert, 8));
    let mut rows = codec.prepare(&p.encode()).unwrap().rows;
    rows[0][codec.k][0] ^= 1;
    let prep = codec.commit_rows(rows).unwrap();
    let h = Header::new(&s, &c, prep.root);
    let rows = prep
        .rows
        .iter()
        .enumerate()
        .map(|(z, r)| {
            (0..codec.k)
                .map(|i| {
                    (
                        i,
                        wavid::Fragment {
                            index: i,
                            data: r[i].clone(),
                            proof: prep.stripes[z].proof(i),
                        },
                    )
                })
                .collect()
        })
        .collect::<Vec<_>>();
    let roots = prep.stripes.iter().map(|t| t.root()).collect::<Vec<_>>();
    let Some(Retrieval::Invalid(fault)) = codec.recover(h.root, &roots, &rows).unwrap() else {
        panic!("coding fault")
    };
    let cert = Certificate {
        header_id: h.id(),
        evidence: Evidence::Storage(fault),
    };
    assert!(certified::verify(&s, &c, &codec, &h, &cert, 8));
    let mut rows = codec.prepare(&p.encode()).unwrap().rows;
    let pos = codec.file_bytes;
    rows[pos / (32 * codec.k)][(pos / 32) % codec.k][pos % 32] = 1;
    let prep = codec.commit_rows(rows).unwrap();
    let h = Header::new(&s, &c, prep.root);
    let proof = codec.source_opening(&prep, pos / 32).unwrap();
    let cert = Certificate {
        header_id: h.id(),
        evidence: Evidence::Storage(StorageFault::Padding(proof)),
    };
    assert!(certified::verify(&s, &c, &codec, &h, &cert, 8));
    let m = WeightedMembership::new(vec![Weight::from(3); 4], Weight::from(4)).unwrap();
    let other = Codec::new(
        &m,
        InstanceId::new(1, Some(1), 0),
        [7; 32],
        codec.file_bytes,
    )
    .unwrap();
    assert!(!certified::verify(&s, &c, &other, &h, &cert, 8));
}

#[test]
fn lazy_receipts_and_semantic_proofs_match_eager_encodings_across_block_sizes() {
    let (s, c, _, o) = fixture();
    let m = WeightedMembership::new(vec![Weight::from(3); 4], Weight::from(4)).unwrap();
    let (original, shares) = ax::generate(&s, &c, &o).unwrap();
    for block_bytes in [32, 34, 64, 126, 128, 256, 510, 4096] {
        let codec = Codec::with_params(
            &m,
            InstanceId::new(1, Some(0), 0),
            [7; 32],
            Public::encoded_len(&s),
            wavid::CodingParams { block_bytes },
        )
        .unwrap();
        let eager = codec.prepare(&original.encode()).unwrap();
        let file = codec.commit_file(original.encode()).unwrap();
        assert_eq!(file.root(), eager.root);
        assert_eq!(file.as_ptr(), file.clone().as_ptr());
        let h = Header::new(&s, &c, file.root());
        for share in &shares {
            let receipt = Receipt::new(&s, &codec, &file, share).unwrap();
            assert_eq!(
                receipt.encode(),
                Receipt::new(&s, &codec, &eager, share).unwrap().encode()
            );
            assert!(receipt.verify(&s, &c, &codec, &h, share.party).is_some());
        }
        assert!(certified::verify_opening(&s, &c, &codec, &h, &o, 8));
        // Canonical fields cross block/stripe boundaries and are deduplicated.
        let boundary = if codec.q > 1 {
            block_bytes * codec.k
        } else {
            block_bytes
        };
        let ranges = [(boundary - 3, 11), (0, 72), (0, 32)];
        assert_eq!(
            bincode::serialize(&certified::openings(&codec, &file, &ranges).unwrap()).unwrap(),
            bincode::serialize(&certified::openings(&codec, &eager, &ranges).unwrap()).unwrap()
        );
        let other = Codec::with_params(
            &m,
            InstanceId::new(1, Some(1), 0),
            [7; 32],
            codec.file_bytes,
            wavid::CodingParams { block_bytes },
        )
        .unwrap();
        assert!(certified::openings(&other, &file, &[(0, 72)]).is_err());
        for kind in 0..5 {
            let mut p = original.clone();
            match kind {
                0 => p.base.true_token[0] ^= 1,
                1 => p.base.wires[2][0] ^= 1,
                2 => {
                    for g in &mut p.base.gates {
                        g[0][0] ^= 1;
                        g[1][0] ^= 1;
                    }
                }
                3 => p.commitment[0] ^= 1,
                _ => p.base.tag[0] ^= 1,
            }
            let eager = codec.prepare(&p.encode()).unwrap();
            let roots = eager.stripes.iter().map(|t| t.root()).collect::<Vec<_>>();
            let fragments = eager
                .rows
                .iter()
                .enumerate()
                .map(|(z, row)| {
                    (0..codec.k)
                        .map(|i| {
                            (
                                i,
                                wavid::Fragment {
                                    index: i,
                                    data: row[i].clone(),
                                    proof: eager.stripes[z].proof(i),
                                },
                            )
                        })
                        .collect()
                })
                .collect::<Vec<_>>();
            let Some(Retrieval::File(recovered)) =
                codec.recover(eager.root, &roots, &fragments).unwrap()
            else {
                panic!("valid storage must recover, even with invalid AX semantics");
            };
            let h = Header::new(&s, &c, recovered.root());
            let terminal = terminal::recover_bounded(&s, &c, &p, &shares, 8).unwrap();
            assert!(!matches!(terminal, Terminal::Success(_)));
            let cert = certified::certify(&s, &codec, &h, &recovered, terminal.clone()).unwrap();
            assert_eq!(
                cert.encode(),
                certified::certify(&s, &codec, &h, &eager, terminal)
                    .unwrap()
                    .encode()
            );
            assert!(certified::verify(&s, &c, &codec, &h, &cert, 8));
            assert!(!certified::verify(&s, &c, &other, &h, &cert, 8));
        }
    }
}

#[test]
fn local_recovery_reuses_only_exact_root_bound_public_bytes() {
    let (s, c, codec, o) = fixture();
    let (original, shares) = ax::generate(&s, &c, &o).unwrap();
    for kind in 0..7 {
        let mut p = original.clone();
        match kind {
            1 => p.base.true_token[0] ^= 1,
            2 => p.base.wires[2][0] ^= 1,
            3 => {
                for g in &mut p.base.gates {
                    g[0][0] ^= 1;
                    g[1][0] ^= 1;
                }
            }
            4 => p.commitment[0] ^= 1,
            5 => p.base.tag[0] ^= 1,
            _ => (),
        }
        let bits = if kind == 6 { 4 } else { 8 };
        let file = codec.commit_file(p.encode()).unwrap();
        let h = Header::new(&s, &c, file.root());
        let source = certified::RecoverySource {
            setup: &s,
            context: &c,
            codec: &codec,
            header: &h,
            public: &p,
            file: &file,
        };
        let cert = source.recover(shares.iter(), bits).unwrap().unwrap();
        assert!(certified::verify(&s, &c, &codec, &h, &cert, bits));
        let legacy = terminal::recover_bounded(&s, &c, &p, &shares, bits).unwrap();
        assert_eq!(
            cert.encode(),
            certified::certify(&s, &codec, &h, &file, legacy)
                .unwrap()
                .encode()
        );
        let mut wrong_public = p.clone();
        wrong_public.commitment[63] ^= 1;
        assert!(
            certified::RecoverySource {
                public: &wrong_public,
                ..source
            }
            .recover(shares.iter(), bits)
            .is_err()
        );
        let mut wrong_header = h.clone();
        wrong_header.root[0] ^= 1;
        assert!(
            certified::RecoverySource {
                header: &wrong_header,
                ..source
            }
            .recover(shares.iter(), bits)
            .is_err()
        );
        let mut wrong_context = c.clone();
        wrong_context.id[0] ^= 1;
        assert!(
            certified::RecoverySource {
                context: &wrong_context,
                ..source
            }
            .recover(shares.iter(), bits)
            .is_err()
        );
    }
    let file = codec.commit_file(original.encode()).unwrap();
    let h = Header::new(&s, &c, file.root());
    let source = certified::RecoverySource {
        setup: &s,
        context: &c,
        codec: &codec,
        header: &h,
        public: &original,
        file: &file,
    };
    assert!(
        source
            .recover(std::iter::repeat_n(&shares[0], 10), 8)
            .unwrap()
            .is_none()
    );
    assert!(source.recover(shares.iter(), 257).is_err());
    let m = WeightedMembership::new(vec![Weight::from(3); 4], Weight::from(4)).unwrap();
    let other = Codec::new(
        &m,
        InstanceId::new(1, Some(1), 0),
        [7; 32],
        codec.file_bytes,
    )
    .unwrap();
    assert!(
        certified::RecoverySource {
            codec: &other,
            ..source
        }
        .recover(shares.iter(), 8)
        .is_err()
    );
}

#[test]
fn authenticated_gate_faults_reject_wrong_branch_masks_and_unused_tokens() {
    let (s, c, codec, o) = fixture();
    let (original, _) = ax::generate(&s, &c, &o).unwrap();
    // Tokens for any chosen gate are deterministic WCSS coins, independent of its ciphertexts.
    let material = crypto::expand(b"AX/derive", &[&c.id(), &o.message, &o.randomness], 128);
    let seed = &material[96..];
    for op in [wcss::Op::And, wcss::Op::Or] {
        let (index, gate) = s
            .circuit()
            .gates()
            .iter()
            .enumerate()
            .find(|(_, g)| g.op == op)
            .unwrap();
        let wire = s.circuit().base() + index;
        let mut p = original.clone();
        p.base.gates[index][0][0] ^= 1;
        let tokens = [gate.left, gate.right].map(|src| {
            crypto::hash(
                b"coins/token",
                &[seed, &c.id(), &(src as u64).to_le_bytes()],
            )
        });
        let t = Terminal::GateFault {
            wire,
            branches: if op == wcss::Op::And { 3 } else { 1 },
            tokens: [
                tokens[0],
                if op == wcss::Op::And {
                    tokens[1]
                } else {
                    [0; 32]
                },
            ],
        };
        let file = codec.commit_file(p.encode()).unwrap();
        let h = Header::new(&s, &c, file.root());
        let cert = certified::certify(&s, &codec, &h, &file, t.clone()).unwrap();
        assert!(terminal::verify(&s, &c, &p, &t));
        assert!(certified::verify(&s, &c, &codec, &h, &cert, 8));
        for branches in [0, 4, 255, if op == wcss::Op::And { 1 } else { 3 }] {
            let mut bad = cert.clone();
            if let Evidence::Semantic {
                fault: Terminal::GateFault { branches: b, .. },
                ..
            } = &mut bad.evidence
            {
                *b = branches;
            }
            assert!(!certified::verify(&s, &c, &codec, &h, &bad, 8));
        }
        let mut bad = cert;
        if let Evidence::Semantic {
            fault: Terminal::GateFault { tokens, .. },
            ..
        } = &mut bad.evidence
        {
            tokens[1][0] ^= 1;
        }
        assert!(!certified::verify(&s, &c, &codec, &h, &bad, 8));
    }
}

#[test]
fn optimized_encoding_matches_preoptimization_snapshot() {
    // Captured from the untouched 2026-10-05 source snapshot, before these optimizations.
    let (s, c, codec, o) = fixture();
    let (p, _) = ax::generate(&s, &c, &o).unwrap();
    assert_eq!(
        p.digest(),
        [
            218, 167, 145, 148, 86, 195, 41, 31, 143, 201, 180, 46, 67, 12, 172, 234, 175, 187, 33,
            231, 47, 148, 26, 181, 209, 182, 58, 56, 34, 136, 197, 122
        ]
    );
    assert_eq!(
        p.base.tag,
        [
            164, 100, 201, 252, 192, 201, 211, 211, 123, 110, 69, 57, 71, 125, 35, 140, 186, 150,
            114, 157, 72, 7, 193, 12, 157, 154, 25, 138, 172, 21, 19, 180
        ]
    );
    assert_eq!(
        codec.commit_file(p.encode()).unwrap().root(),
        [
            246, 180, 68, 82, 133, 56, 190, 157, 31, 10, 7, 79, 26, 176, 106, 68, 3, 142, 130, 44,
            55, 110, 58, 254, 231, 220, 128, 41, 137, 6, 44, 235
        ]
    );
    let raw = p.encode();
    assert!(p.matches_encoded(&raw));
    assert_eq!(p.digest(), crypto::hash(b"public", &[&raw]));
    for offset in (0..raw.len()).step_by(17) {
        let mut changed = raw.clone();
        changed[offset] ^= 1;
        assert!(!p.matches_encoded(&changed));
    }
    assert!(!p.matches_encoded(&raw[..raw.len() - 1]));
    let mut wrong = p.clone();
    wrong.base.gates.pop();
    assert!(!p.same_encoding(&wrong));
}

#[test]
fn python_cost_model_matches_rust_serialization() {
    let cases: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/coding-layout.json")).unwrap();
    for row in cases.as_array().unwrap() {
        let weights = row["weights"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap())
            .collect::<Vec<_>>();
        let threshold = row["threshold"].as_u64().unwrap();
        let strings = weights.iter().map(u64::to_string).collect::<Vec<_>>();
        let s = Setup::new(
            Policy::from_strings(&strings, &threshold.to_string()).unwrap(),
            Limits::default(),
        )
        .unwrap();
        let c = Context::new(
            &s,
            Instance {
                session: [3; 32],
                epoch: 1,
                dealer: 0,
            },
            vec![],
        )
        .unwrap();
        let membership = WeightedMembership::new(
            weights.iter().copied().map(Weight::from).collect(),
            Weight::from(threshold),
        )
        .unwrap();
        let b = row["cost"]["block_bytes"].as_u64().unwrap() as usize;
        let instance = InstanceId::new(1, Some(0), 0);
        let codec = Codec::with_params(
            &membership,
            instance,
            [7; 32],
            Public::encoded_len(&s),
            wavid::CodingParams { block_bytes: b },
        )
        .unwrap();
        assert_eq!(
            s.circuit().gates().len() as u64,
            row["geometry"]["gates"].as_u64().unwrap()
        );
        assert_eq!(
            Public::encoded_len(&s) as u64,
            row["geometry"]["public_bytes"].as_u64().unwrap()
        );
        assert_eq!(codec.q as u64, row["cost"]["stripes"].as_u64().unwrap());
        let opening = Opening {
            message: [0; 32],
            randomness: [4; 32],
        };
        let (p, shares) = ax::generate(&s, &c, &opening).unwrap();
        let prepared = codec.prepare(&p.encode()).unwrap();
        for (i, share) in shares.iter().enumerate() {
            let bytes = codec.encode_bundle(i, &prepared.bundles[i]).unwrap();
            assert_eq!(
                bytes.len() as u64,
                row["cost"]["bundle_bytes"][i].as_u64().unwrap()
            );
            let receipt = Receipt::new(&s, &codec, &prepared, share).unwrap();
            assert_eq!(
                receipt.encode().len() as u64,
                row["cost"]["receipt_bytes"][i].as_u64().unwrap()
            );
            assert_eq!(
                bincode::serialized_size(&receipt.fields[0]).unwrap(),
                row["cost"]["source_opening_bytes"].as_u64().unwrap()
            );
        }
        let chunk = wavid::ProtMsg {
            instance,
            kind: wavid::Kind::Data {
                index: 0,
                bytes: vec![0; 123],
            },
        };
        assert_eq!(bincode::serialized_size(&chunk).unwrap(), 41 + 123);
        let request = wavid::ProtMsg {
            instance,
            kind: wavid::Kind::Request([0; 32]),
        };
        assert_eq!(bincode::serialized_size(&request).unwrap(), 61);
        assert_eq!(
            Certificate {
                header_id: [0; 32],
                evidence: Evidence::Success(opening)
            }
            .encode()
            .len(),
            100
        );
    }
}
