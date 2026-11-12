use crypto::Block;
use sdc_types::{InstanceId, WeightedMembership};
use types::{Error, Instance, Policy};
use wavid::{Codec, CodingParams};
use wiawvss::{
    Context, Limits, Opening, PrivateShare, Public, PublicView, Setup, ax,
    certified::{self, Certificate, Evidence, Header, Layout},
    terminal::{self, Terminal},
};

fn setup(w: &[u64], t: u64) -> Setup {
    Setup::new_clean(
        Policy::new(w.iter().map(|&x| x.into()).collect(), t.into()).unwrap(),
        Limits::default(),
    )
    .unwrap()
}
fn context(s: &Setup) -> Context {
    Context::new(
        s,
        Instance {
            session: [17; 32],
            epoch: 2,
            dealer: 0,
        },
        b"boundary-tests".to_vec(),
    )
    .unwrap()
}
fn opening() -> Opening {
    let mut message = [0; 32];
    message[31] = 19;
    Opening {
        message,
        randomness: [31; 32],
    }
}
fn codec(s: &Setup, b: usize) -> Codec {
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
        InstanceId::new(2, Some(0), 0),
        [13; 32],
        Public::encoded_len(s),
        CodingParams { block_bytes: b },
    )
    .unwrap()
}
fn full_labels(s: &Setup, c: &Context, p: &Public, shares: &[PrivateShare]) -> Vec<Block> {
    let mut labels = vec![[0; 32]; s.circuit().nodes()];
    labels[1] = p.base.true_token;
    for share in shares {
        labels[share.party + 2] = share.token;
    }
    for (i, g) in s.circuit().gates().iter().enumerate() {
        let (branches, tokens) = match g.op {
            wcss::Op::And => (3, [labels[g.left], labels[g.right]]),
            wcss::Op::Or => (1, [labels[g.left], [0; 32]]),
        };
        labels[s.circuit().base() + i] =
            wcss::evaluate_gate(s, &c.id(), i, branches, &tokens, |j| p.base.correction(j))
                .unwrap();
    }
    labels
}

#[test]
fn boundary_bytes_bind_the_retained_record_with_a_separate_tag_domain() {
    let s = setup(&[3, 5, 9, 17, 33, 65], 44);
    let c = context(&s);
    let o = opening();
    let (p, shares) = ax::generate(&s, &c, &o).unwrap();
    let mut expanded = [0; 128];
    crypto::expand_into(
        b"AX/derive",
        &[&c.id(), &o.message, &o.randomness],
        &mut expanded,
    );
    let key: Block = expanded[64..96].try_into().unwrap();
    let seed: Block = expanded[96..].try_into().unwrap();
    let (full, tokens) = wcss::share(&s, &c.id(), &key, &seed);
    assert_ne!(p.base.tag, full.tag);
    let root = full_labels(&s, &c, &p, &shares)[s.circuit().output()];
    assert_eq!(p.base.tag, retained_tag(&s, &c, &p, &root));
    let public_only = wcss::share_pvr_public(&s, &c.id(), &key, &seed);
    assert_eq!(p.base, public_only);
    assert_eq!(p, ax::generate_public(&s, &c, &o).unwrap());
    assert_eq!(p.base.inputs, full.inputs);
    assert_eq!(p.base.corrections, full.corrections);
    assert_eq!(
        p.base.wires,
        s.boundary()
            .unwrap()
            .wires()
            .iter()
            .map(|&w| full.wires[w])
            .collect::<Vec<_>>()
    );
    assert!(p.base.wires.len() < full.wires.len());
    for (share, token) in shares.iter().zip(tokens.iter()) {
        assert_eq!(&share.token, token);
    }
    assert_eq!(&p.encode()[..8], b"HWAX0003");
    for old_magic in [b"HWAX0001", b"HWAX0002"] {
        let mut bytes = p.encode();
        bytes[..8].copy_from_slice(old_magic);
        assert!(Public::decode(&s, &c, &bytes).is_err());
        assert!(PublicView::decode(&s, &c, &bytes).is_err());
    }
    let old_id = crypto::hash(
        b"setup/clean-v1/gcd-ordered-merge/and0-or1/columns4/p25519/token256",
        &[&s.circuit().encode(), &s.boundary().unwrap().id()],
    );
    assert_ne!(s.id(), old_id);
    assert!(ax::verify_opening(&s, &c, &p, &o));
    assert_eq!(Public::decode(&s, &c, &p.encode()).unwrap(), p);
}

#[test]
fn every_authorized_coalition_completes_across_modules_without_all_entries() {
    let mut views = 0;
    for (weights, t) in [
        (vec![1], 1),
        (vec![1, 1], 1),
        (vec![3, 5, 9, 17, 33, 65], 44),
        (vec![17, 24, 31, 38, 45, 52, 59, 66], 110),
    ] {
        let s = setup(&weights, t);
        let c = context(&s);
        let o = opening();
        let (p, shares) = ax::generate(&s, &c, &o).unwrap();
        let bytes = p.encode();
        let view = PublicView::decode(&s, &c, &bytes).unwrap();
        if weights.len() >= 6 {
            assert!(s.boundary().unwrap().modules().len() >= 2);
        }
        for mask in 0..1usize << weights.len() {
            let selected: Vec<_> = shares
                .iter()
                .enumerate()
                .filter(|(i, _)| mask & (1 << i) != 0)
                .map(|(_, s)| s.clone())
                .collect();
            let expected = s
                .circuit()
                .policy()
                .authorized(selected.iter().map(|s| s.party))
                .unwrap();
            for result in [
                terminal::recover(&s, &c, &p, &selected),
                terminal::recover_bounded_iter(&s, &c, &view, &selected, 8),
            ] {
                if expected {
                    assert!(matches!(result.unwrap(),Terminal::Success(x) if x==o));
                } else {
                    assert!(matches!(result, Err(Error::InsufficientShares)));
                }
            }
            views += 1;
        }
    }
    println!("boundary coalition views: {views} (owned and borrowed recovery)");
}

#[test]
fn partial_entry_module_fault_is_publicly_verifiable_and_forgeries_are_rejected() {
    let s = setup(&[1, 1, 1], 1);
    let c = context(&s);
    let o = opening();
    let (good, shares) = ax::generate(&s, &c, &o).unwrap();
    let plan = s.boundary().unwrap();
    let out = s.circuit().output();
    let mut p = good.clone();
    p.base.wires[plan.index(out).unwrap()][0] ^= 1;
    let t = terminal::recover(&s, &c, &p, &shares[..1]).unwrap();
    let Terminal::ModuleFault {
        module,
        output,
        inputs,
    } = &t
    else {
        panic!("{t:?}")
    };
    assert_eq!(inputs.len(), 1);
    assert_eq!(plan.modules()[*module].inputs.len(), 3);
    assert!(terminal::verify(&s, &c, &p, &t));
    assert!(!terminal::verify(&s, &c, &good, &t));
    let encoded = t.encode(&p);
    assert_eq!(Terminal::decode(&p, &encoded).unwrap(), t);
    assert!(Terminal::decode(&good, &encoded).is_err());
    let mut forgeries = vec![
        Terminal::ModuleFault {
            module: *module,
            output: *output,
            inputs: vec![],
        },
        Terminal::ModuleFault {
            module: usize::MAX,
            output: *output,
            inputs: inputs.clone(),
        },
        Terminal::ModuleFault {
            module: *module,
            output: 2,
            inputs: inputs.clone(),
        },
        Terminal::ModuleFault {
            module: *module,
            output: *output,
            inputs: vec![inputs[0], inputs[0]],
        },
        // A prover must not turn the target or an internal wire into an entrance.
        Terminal::ModuleFault {
            module: *module,
            output: *output,
            inputs: vec![(*output, [1; 32])],
        },
        Terminal::GateFault {
            wire: out,
            branches: 1,
            tokens: [shares[0].token, [0; 32]],
        },
    ];
    let mut wrong = inputs.clone();
    wrong[0].1[0] ^= 1;
    forgeries.push(Terminal::ModuleFault {
        module: *module,
        output: *output,
        inputs: wrong,
    });
    for forged in forgeries {
        assert!(!terminal::verify(&s, &c, &p, &forged));
    }
    for b in [32, 64, 1024] {
        let codec = codec(&s, b);
        let file = codec.commit_file(p.encode()).unwrap();
        let h = Header::new(&s, &c, file.root());
        let cert = certified::certify(&s, &codec, &h, &file, t.clone()).unwrap();
        assert!(certified::verify(&s, &c, &codec, &h, &cert, 8));
        assert_eq!(
            Certificate::decode_for_setup(&s, &codec, &cert.encode())
                .unwrap()
                .encode(),
            cert.encode()
        );
        let mut bad = cert.clone();
        if let Evidence::Semantic { fields, .. } = &mut bad.evidence {
            fields.pop();
        }
        assert!(!certified::verify(&s, &c, &codec, &h, &bad, 8));
        let mut bad = cert.clone();
        if let Evidence::Semantic { fields, .. } = &mut bad.evidence {
            fields[0].fragment.data[0] ^= 1;
        }
        assert!(!certified::verify(&s, &c, &codec, &h, &bad, 8));
        let mut bad = cert.clone();
        if let Evidence::Semantic { fields, .. } = &mut bad.evidence {
            fields.push(fields[0].clone());
        }
        assert!(!certified::verify(&s, &c, &codec, &h, &bad, 8));
        let mut cross = h.clone();
        cross.context_id[0] ^= 1;
        assert!(!certified::verify(&s, &c, &codec, &cross, &cert, 8));
    }
}

#[test]
fn unused_corrections_must_be_opened_and_canonical_checked() {
    let s = setup(&[3, 3], 1);
    let c = context(&s);
    let o = opening();
    let (mut p, shares) = ax::generate(&s, &c, &o).unwrap();
    let out = s.circuit().output();
    let root = s.circuit().gates()[out - s.circuit().base()];
    assert!(root.left >= 2 && root.left < s.circuit().base());
    let left = &shares[root.left - 2..root.left - 1];
    let right = &shares[root.right - 2..root.right - 1];
    let correction_index = s.correction_index(out - s.circuit().base(), 1).unwrap();
    // Left path does not read this correction. It must still fail full Canon.
    p.base.corrections[correction_index][0] ^= 1;
    assert!(matches!(
        terminal::recover(&s, &c, &p, left).unwrap(),
        Terminal::RootFault { .. }
    ));
    // Right path exercises the corruption and yields a module counterexample.
    assert!(matches!(
        terminal::recover(&s, &c, &p, right).unwrap(),
        Terminal::ModuleFault { .. }
    ));
    p.base.wires[s.boundary().unwrap().index(out).unwrap()][0] ^= 1;
    let t = terminal::recover(&s, &c, &p, left).unwrap();
    let codec = codec(&s, 32);
    let file = codec.commit_file(p.encode()).unwrap();
    let h = Header::new(&s, &c, file.root());
    let mut cert = certified::certify(&s, &codec, &h, &file, t.clone()).unwrap();
    assert!(certified::verify(&s, &c, &codec, &h, &cert, 8));
    let correction = Layout::new(&s).correction(correction_index);
    // Last block of the correction is not shared with the output digest.
    let required = (correction + 31) / 32;
    if let Evidence::Semantic { fields, .. } = &mut cert.evidence {
        let count = fields.len();
        fields.retain(|p| p.stripe * codec.k + p.fragment.index != required);
        assert_eq!(fields.len() + 1, count);
    }
    assert!(!certified::verify(&s, &c, &codec, &h, &cert, 8));
}

#[test]
fn authenticated_but_insufficient_entries_do_not_prove_a_module_failure() {
    let s = setup(&[1, 1, 10], 2);
    let c = context(&s);
    let (mut p, shares) = ax::generate(&s, &c, &opening()).unwrap();
    let plan = s.boundary().unwrap();
    let output = s.circuit().output();
    p.base.wires[plan.index(output).unwrap()][0] ^= 1;
    let (module, m) = plan
        .modules()
        .iter()
        .enumerate()
        .find(|(_, m)| m.outputs.contains(&output))
        .unwrap();
    assert!(m.inputs.contains(&2));
    let forged = Terminal::ModuleFault {
        module,
        output,
        inputs: vec![(2, shares[0].token)],
    };
    assert!(!terminal::verify(&s, &c, &p, &forged));
    let codec = codec(&s, 64);
    let file = codec.commit_file(p.encode()).unwrap();
    let header = Header::new(&s, &c, file.root());
    let certificate = certified::certify(&s, &codec, &header, &file, forged).unwrap();
    // Every field and entry token authenticates, but no exit is reachable.
    assert!(!certified::verify(&s, &c, &codec, &header, &certificate, 8));
}

#[test]
fn all_retained_noninput_fields_either_reject_early_or_reach_root_fault() {
    let s = setup(&[3, 5, 9, 17, 33, 65], 44);
    let c = context(&s);
    let o = opening();
    let (good, shares) = ax::generate(&s, &c, &o).unwrap();
    let mut bads = vec![];
    for i in 0..good.base.wires.len() {
        let mut p = good.clone();
        p.base.wires[i][0] ^= 1;
        bads.push(p);
    }
    for i in 0..good.base.corrections.len() {
        let mut p = good.clone();
        p.base.corrections[i][0] ^= 1;
        bads.push(p);
    }
    for i in 0..6 {
        let mut p = good.clone();
        match i {
            0 => p.base.true_token[0] ^= 1,
            1 => p.base.tag[0] ^= 1,
            2 => p.base.encrypted_key[0] ^= 1,
            3 => p.ciphertext[0] ^= 1,
            4 => p.randomness_ciphertext[0] ^= 1,
            _ => p.commitment[0] ^= 1,
        }
        bads.push(p);
    }
    let codec = codec(&s, 64);
    let mut checks = 0;
    let mut modules = 0;
    for p in &bads {
        assert!(!ax::verify_opening(&s, &c, p, &o));
        for mask in 0..64usize {
            let selected: Vec<_> = shares
                .iter()
                .enumerate()
                .filter(|(i, _)| mask & (1 << i) != 0)
                .map(|(_, s)| s.clone())
                .collect();
            if !s
                .circuit()
                .policy()
                .authorized(selected.iter().map(|s| s.party))
                .unwrap()
            {
                continue;
            }
            let t = terminal::recover(&s, &c, p, &selected).unwrap();
            assert!(!matches!(t, Terminal::Success(_)));
            assert!(terminal::verify(&s, &c, p, &t));
            if matches!(t, Terminal::ModuleFault { .. }) {
                modules += 1;
            }
            checks += 1;
        }
        // Actual source openings, including unaligned fields, for every corruption.
        let file = codec.commit_file(p.encode()).unwrap();
        let h = Header::new(&s, &c, file.root());
        let t = terminal::recover(&s, &c, p, &shares).unwrap();
        let cert = certified::certify(&s, &codec, &h, &file, t).unwrap();
        assert!(certified::verify(&s, &c, &codec, &h, &cert, 8));
        assert!(cert.encode().len() <= certified::max_evidence_bytes_for_setup(&s, &codec));
    }
    assert!(modules > 0);
    println!(
        "boundary malicious-record coalition checks: {checks}; module faults: {modules}; records: {}",
        bads.len()
    );
}

#[test]
fn projected_format_fault_and_cached_success_are_bound_to_the_full_file() {
    let s = setup(&[3, 5, 9, 17, 33, 65], 44);
    let c = context(&s);
    let o = opening();
    let (p, _) = ax::generate(&s, &c, &o).unwrap();
    let codec = codec(&s, 64);
    let mut raw = p.encode();
    raw[..8].copy_from_slice(b"HWAX0001");
    assert!(Public::decode(&s, &c, &raw).is_err());
    let file = codec.commit_file(raw).unwrap();
    let h = Header::new(&s, &c, file.root());
    let cert = Certificate {
        header_id: h.id(),
        evidence: Evidence::Format(certified::openings(&codec, &file, &[(0, 72)]).unwrap()),
    };
    assert!(certified::verify(&s, &c, &codec, &h, &cert, 8));
    let honest = codec.commit_file(p.encode()).unwrap();
    let h = Header::new(&s, &c, honest.root());
    let cert = Certificate {
        header_id: h.id(),
        evidence: Evidence::Success(o),
    };
    assert!(certified::verify_with_file(
        &s,
        &c,
        &codec,
        &h,
        &cert,
        8,
        Some(&honest)
    ));
    assert!(!certified::verify_with_file(
        &s,
        &c,
        &codec,
        &h,
        &cert,
        8,
        Some(&file)
    ));
}

#[test]
fn aptos_module_evidence_serialization_is_bounded_at_both_block_sizes() {
    #[derive(serde::Deserialize)]
    struct Case {
        n: usize,
        weights: Vec<String>,
        threshold: String,
        boundary_bytes: usize,
    }
    let cases: Vec<Case> = serde_json::from_str(include_str!("fixtures/clean-aptos.json")).unwrap();
    for case in cases {
        let s = Setup::new_clean(
            Policy::from_strings(&case.weights, &case.threshold).unwrap(),
            Limits::default(),
        )
        .unwrap();
        let c = context(&s);
        let (good, shares) = ax::generate(&s, &c, &opening()).unwrap();
        assert_eq!(good.encode().len(), case.boundary_bytes);
        let labels = full_labels(&s, &c, &good, &shares);
        let plan = s.boundary().unwrap();
        let (id, m) = plan
            .modules()
            .iter()
            .enumerate()
            .max_by_key(|(_, m)| m.corrections.len() + m.inputs.len())
            .unwrap();
        let output = m.outputs[0];
        let mut p = good.clone();
        p.base.wires[plan.index(output).unwrap()][0] ^= 1;
        let fault = Terminal::ModuleFault {
            module: id,
            output,
            inputs: m.inputs.iter().map(|&w| (w, labels[w])).collect(),
        };
        assert!(terminal::verify(&s, &c, &p, &fault));
        for b in [32, 1024] {
            let codec = codec(&s, b);
            let file = codec.commit_file(p.encode()).unwrap();
            let h = Header::new(&s, &c, file.root());
            let cert = certified::certify(&s, &codec, &h, &file, fault.clone()).unwrap();
            let bytes = cert.encode();
            let bound = certified::max_module_evidence_bytes(&s, &codec);
            assert!(bytes.len() <= bound);
            assert!(certified::verify(&s, &c, &codec, &h, &cert, 8));
            assert_eq!(
                Certificate::decode_for_setup(&s, &codec, &bytes)
                    .unwrap()
                    .encode(),
                bytes
            );
            let mut trailing = bytes.clone();
            trailing.push(0);
            assert!(Certificate::decode_for_setup(&s, &codec, &trailing).is_err());
            println!(
                "Aptos{}: block={}, modules={}, retained={}, module_sample={} B, module_bound={} B",
                case.n,
                b,
                plan.modules().len(),
                plan.wires().len(),
                bytes.len(),
                bound
            );
        }
    }
}

// Independent reference framing: this hashes the encoded retained record,
// rather than calling the generator's tag helper.
fn retained_tag(s: &Setup, c: &Context, p: &Public, root: &Block) -> Block {
    let mut body = p.base.clone();
    body.tag = [0; 32];
    crypto::hash(
        b"transcript/pvr-retained/v1",
        &[
            &c.id(),
            &s.boundary().unwrap().id(),
            &(s.circuit().output() as u64).to_le_bytes(),
            root,
            &body.encode(),
        ],
    )
}

#[test]
fn retagged_unused_correction_and_bad_tag_remain_publicly_rejectable() {
    let s = setup(&[3, 3], 1);
    let c = context(&s);
    let o = opening();
    let (good, shares) = ax::generate(&s, &c, &o).unwrap();
    let out = s.circuit().output();
    let gate = s.circuit().gates()[out - s.circuit().base()];
    let root = full_labels(&s, &c, &good, &shares)[out];
    let left = &shares[gate.left - 2..gate.left - 1];
    let right = &shares[gate.right - 2..gate.right - 1];
    let codec = codec(&s, 32);
    let mut retagged = good.clone();
    retagged.base.corrections[s.correction_index(out - s.circuit().base(), 1).unwrap()][0] ^= 1;
    retagged.base.tag = retained_tag(&s, &c, &retagged, &root);
    assert!(matches!(
        terminal::recover(&s, &c, &retagged, right).unwrap(),
        Terminal::ModuleFault { .. }
    ));
    let mut bad_tag = good.clone();
    bad_tag.base.tag[0] ^= 1;
    // Old full-record tag is also invalid even under the new file magic.
    let mut expanded = [0; 128];
    crypto::expand_into(
        b"AX/derive",
        &[&c.id(), &o.message, &o.randomness],
        &mut expanded,
    );
    let mut old_tag = good.clone();
    old_tag.base.tag = wcss::share_public(
        &s,
        &c.id(),
        &expanded[64..96].try_into().unwrap(),
        &expanded[96..].try_into().unwrap(),
    )
    .tag;
    for p in [retagged, bad_tag, old_tag] {
        assert!(!ax::verify_opening(&s, &c, &p, &o));
        let bytes = p.encode();
        let view = PublicView::decode(&s, &c, &bytes).unwrap();
        let t = terminal::recover_bounded_iter(&s, &c, &view, left.iter(), 8).unwrap();
        assert!(matches!(t, Terminal::RootFault { .. }));
        assert!(terminal::verify(&s, &c, &p, &t));
        assert!(!terminal::verify(&s, &c, &good, &t));
        let file = codec.commit_file(bytes).unwrap();
        let h = Header::new(&s, &c, file.root());
        let cert = certified::certify(&s, &codec, &h, &file, t).unwrap();
        assert!(certified::verify(&s, &c, &codec, &h, &cert, 8));
        let success = Certificate {
            header_id: h.id(),
            evidence: Evidence::Success(o.clone()),
        };
        assert!(!certified::verify(&s, &c, &codec, &h, &success, 8));
        assert!(!certified::verify_with_file(
            &s,
            &c,
            &codec,
            &h,
            &success,
            8,
            Some(&file)
        ));
    }
}

#[test]
fn retained_generator_preserves_full_and_compact_css_interfaces() {
    let policy = Policy::new(vec![3u64.into(), 5u64.into(), 9u64.into()], 6u64.into()).unwrap();
    for s in [
        Setup::new(policy.clone(), Limits::default()).unwrap(),
        Setup::new_optimized(policy.clone(), Limits::default()).unwrap(),
        Setup::new_clean(policy, Limits::default()).unwrap(),
    ] {
        let c = context(&s);
        let (full, shares) = wcss::share(&s, &c.id(), &[19; 32], &[23; 32]);
        let all: Vec<_> = shares.iter().copied().enumerate().collect();
        assert_eq!(
            wcss::reconstruct(&s, &c.id(), &full, &all).unwrap(),
            [19; 32]
        );
        let (compact, tokens) = wcss::compact::share(&s, &c.id(), &[19; 32], &[23; 32]);
        let all: Vec<_> = tokens.iter().copied().enumerate().collect();
        assert_eq!(
            wcss::compact::reconstruct(&s, &c.id(), &compact, &all).unwrap(),
            [19; 32]
        );
        let (pvr, pvr_tokens) = wcss::share_pvr(&s, &c.id(), &[19; 32], &[23; 32]);
        assert_eq!(shares, pvr_tokens);
        assert_eq!(
            pvr,
            wcss::share_pvr_public(&s, &c.id(), &[19; 32], &[23; 32])
        );
        if s.boundary().is_none() {
            assert_eq!(full, pvr);
        }
    }
}

#[test]
fn retained_tag_material_cache_accepts_only_the_complete_canonical_record() {
    let s = setup(&[3, 5, 9, 17, 33, 65], 44);
    let c = context(&s);
    let o = opening();
    let (good, shares) = ax::generate(&s, &c, &o).unwrap();
    let codec = codec(&s, 64);
    for corrupt in [false, true] {
        let mut p = good.clone();
        if corrupt {
            p.base.tag[0] ^= 1;
        }
        let file = codec.commit_file(p.encode()).unwrap();
        let h = Header::new(&s, &c, file.root());
        let material = wavid::VerifiedMaterial::new(std::sync::Arc::new(codec.clone()), h.root);
        let success = Certificate {
            header_id: h.id(),
            evidence: Evidence::Success(o.clone()),
        };
        let result = certified::verify_with_material(&s, &c, &codec, &h, &success, 8, &material);
        if corrupt {
            assert!(result.is_none());
            assert!(material.file().unwrap().is_none());
            let t = terminal::recover(&s, &c, &p, &shares).unwrap();
            assert!(matches!(t, Terminal::RootFault { .. }));
            let reject = certified::certify(&s, &codec, &h, &file, t).unwrap();
            assert!(matches!(
                certified::verify_with_material(&s, &c, &codec, &h, &reject, 8, &material),
                Some(certified::VerifiedEvidence::Rejection)
            ));
            assert!(material.file().unwrap().is_none());
        } else {
            let Some(certified::VerifiedEvidence::Success(file)) = result else {
                panic!("honest file rejected")
            };
            assert!(p.matches_encoded(&file));
            let encoded = material.stats().unwrap().encoded_stripes;
            assert!(
                certified::verify_with_material(&s, &c, &codec, &h, &success, 8, &material)
                    .is_some()
            );
            assert_eq!(encoded, material.stats().unwrap().encoded_stripes);
        }
    }
}
