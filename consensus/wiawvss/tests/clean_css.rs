use sdc_types::{InstanceId, Weight, WeightedMembership};
use types::{Error, Instance, Policy};
use wavid::Codec;
use wiawvss::{
    Context, Limits, Opening, Public, PublicView, Setup, ax,
    certified::{self, Evidence, Header, Layout, Receipt},
    compact,
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
            session: [5; 32],
            epoch: 7,
            dealer: 0,
        },
        b"clean-module-test/v1".to_vec(),
    )
    .unwrap()
}
fn opening() -> Opening {
    let mut message = [0; 32];
    message[31] = 17;
    Opening {
        message,
        randomness: [61; 32],
    }
}
fn codec(s: &Setup) -> Codec {
    let p = s.circuit().policy();
    let m = WeightedMembership::new(
        p.weights()
            .iter()
            .map(|w| w.to_string().parse::<Weight>().unwrap())
            .collect(),
        p.threshold().to_string().parse().unwrap(),
    )
    .unwrap();
    Codec::new(
        &m,
        InstanceId::new(7, Some(0), 0),
        [23; 32],
        Public::encoded_len(s),
    )
    .unwrap()
}

#[test]
fn full_and_compact_ax_share_labels_and_recover_every_weighted_coalition() {
    for (w, t) in [
        (vec![1], 1),
        (vec![1, 1], 1),
        (vec![2, 3, 5], 6),
        (vec![3; 4], 4),
        (vec![2, 4, 6, 8], 9),
        (vec![1, 3, 4, 7, 9], 8),
    ] {
        let s = setup(&w, t);
        let c = context(&s);
        let o = opening();
        let (full, shares) = ax::generate(&s, &c, &o).unwrap();
        let (small, compact_shares) = compact::generate(&s, &c, &o).unwrap();
        assert_eq!(shares, compact_shares);
        let raw = full.encode();
        let small_raw = small.encode();
        assert_eq!(raw.len() - small_raw.len(), 32 * s.pvr_wire_count());
        assert_eq!(Public::decode(&s, &c, &raw).unwrap(), full);
        assert_eq!(compact::Public::decode(&s, &c, &small_raw).unwrap(), small);
        let view = PublicView::decode(&s, &c, &raw).unwrap();
        let small_view = compact::PublicView::decode(&s, &c, &small_raw).unwrap();
        assert_eq!(small_view.digest(), small.digest());
        for mask in 0..1usize << w.len() {
            let selected: Vec<_> = shares
                .iter()
                .enumerate()
                .filter(|(i, _)| mask & (1 << i) != 0)
                .map(|(_, x)| x.clone())
                .collect();
            let authorized = s
                .circuit()
                .policy()
                .authorized(selected.iter().map(|x| x.party))
                .unwrap();
            let a = ax::reconstruct(&s, &c, &full, &selected);
            let b = compact::reconstruct(&s, &c, &small, &selected);
            let borrowed = small_view.reconstruct(&s, &c, &selected);
            let terminal = terminal::recover_bounded_iter(&s, &c, &view, &selected, 8);
            if authorized {
                let a = a.unwrap();
                assert_eq!(a.opening, o);
                assert_eq!(a.shares, shares);
                assert_eq!(b.unwrap().opening, o);
                assert_eq!(borrowed.unwrap().opening, o);
                assert!(matches!(terminal.unwrap(),Terminal::Success(x) if x==o));
            } else {
                assert!(matches!(a, Err(Error::InsufficientShares)));
                assert!(matches!(b, Err(Error::InsufficientShares)));
                assert!(matches!(borrowed, Err(Error::InsufficientShares)));
                assert!(matches!(terminal, Err(Error::InsufficientShares)));
            }
        }
        let old = Setup::new(s.circuit().policy().clone(), Limits::default()).unwrap();
        assert!(Public::decode(&old, &c, &raw).is_err());
        assert!(compact::Public::decode(&old, &c, &small_raw).is_err());
        let mut changed = c.clone();
        changed.id[0] ^= 1;
        assert!(PublicView::decode(&s, &changed, &raw).is_err());
        for len in [0, 1, 71, raw.len() - 1] {
            assert!(PublicView::decode(&s, &c, &raw[..len]).is_err());
        }
    }
}

#[test]
fn full_canon_rejects_an_unused_or_correction_even_with_a_valid_css_tag() {
    let s = setup(&[1, 1], 1);
    let c = context(&s);
    let o = opening();
    assert_eq!(s.circuit().gates().len(), 1);
    let (mut full, shares) = ax::generate(&s, &c, &o).unwrap();
    let (small, _) = compact::generate(&s, &c, &o).unwrap();
    let root =
        wcss::evaluate_gate(&s, &c.id(), 0, 1, &[shares[0].token, [0; 32]], |_| panic!()).unwrap();
    full.base.corrections[0][0] ^= 1;
    full.base.tag = crypto::hash_with_tail(
        b"transcript",
        &[&c.id(), &root],
        full.base.byte_len(),
        full.base.encoded_parts(&[0; 32]),
    );
    // The exercised left branch and inner tag are now valid. Full AX regeneration
    // must still reject the modified, unexercised right branch.
    assert!(wcss::reconstruct(&s, &c.id(), &full.base, &[(0, shares[0].token)]).is_ok());
    assert!(!ax::verify_opening(&s, &c, &full, &o));
    assert!(ax::reconstruct(&s, &c, &full, &shares[..1]).is_err());
    assert!(matches!(
        terminal::recover(&s, &c, &full, &shares[..1]).unwrap(),
        Terminal::RootFault { .. }
    ));

    let mut bytes = small.encode();
    let end = 72 + wcss::compact::Public::encoded_len(&s);
    bytes[72 + 32 + 32 * 2] ^= 1;
    let tag = crypto::hash_with_tail(
        b"transcript",
        &[&c.id(), &root],
        end - 72,
        [&bytes[72..end - 32], &[0; 32]],
    );
    bytes[end - 32..end].copy_from_slice(&tag);
    let inner = wcss::compact::Public::decode(&s, &bytes[72..end]).unwrap();
    assert!(wcss::compact::reconstruct(&s, &c.id(), &inner, &[(0, shares[0].token)]).is_ok());
    let tampered = compact::Public::decode(&s, &c, &bytes).unwrap();
    assert!(!compact::verify_opening(&s, &c, &tampered, &o));
    assert!(compact::reconstruct(&s, &c, &tampered, &shares[..1]).is_err());
    assert!(
        compact::PublicView::decode(&s, &c, &bytes)
            .unwrap()
            .reconstruct(&s, &c, &shares[..1])
            .is_err()
    );
}

#[test]
fn generated_receipts_and_each_fault_verify_without_a_full_download() {
    let s = setup(&[3; 4], 4);
    let c = context(&s);
    let o = opening();
    let codec = codec(&s);
    let (original, shares) = ax::generate(&s, &c, &o).unwrap();
    let prep = codec.prepare(&original.encode()).unwrap();
    let honest = Header::new(&s, &c, prep.root);
    for share in &shares {
        let receipt = Receipt::new(&s, &codec, &prep, share).unwrap();
        assert!(
            receipt
                .verify(&s, &c, &codec, &honest, share.party)
                .is_some()
        );
    }
    let mut bads = vec![];
    let mut p = original.clone();
    p.base.true_token[0] ^= 1;
    bads.push(p);
    let mut p = original.clone();
    p.base.wires[2][0] ^= 1;
    bads.push(p);
    let mut p = original.clone();
    p.base.corrections[0][0] ^= 1;
    bads.push(p);
    let mut p = original.clone();
    p.base.tag[0] ^= 1;
    bads.push(p);
    let mut p = original.clone();
    p.commitment[0] ^= 1;
    bads.push(p);
    let plan = s.boundary().unwrap();
    let mut p = original.clone();
    p.base.wires[plan.index(s.circuit().output()).unwrap()][0] ^= 1;
    bads.push(p);
    let mut module_seen = false;
    for p in bads {
        let raw = p.encode();
        let prep = codec.prepare(&raw).unwrap();
        let h = Header::new(&s, &c, prep.root);
        let t = terminal::recover_bounded(&s, &c, &p, &shares, 8).unwrap();
        assert!(!matches!(t, Terminal::Success(_)));
        assert!(terminal::verify(&s, &c, &p, &t));
        assert!(!terminal::verify(&s, &c, &original, &t));
        let view = PublicView::decode(&s, &c, &raw).unwrap();
        assert_eq!(
            terminal::recover_bounded_iter(&s, &c, &view, &shares, 8).unwrap(),
            t
        );
        if let Terminal::ModuleFault { module, .. } = &t {
            module_seen = true;
            let ranges = Layout::new(&s).ranges(&s, &t).unwrap();
            let corrections = &plan.modules()[*module].corrections;
            if !corrections.is_empty() {
                assert!(ranges.contains(&(
                    Layout::new(&s).correction(corrections.start),
                    32 * corrections.len()
                )));
            }
        }
        let cert = certified::certify(&s, &codec, &h, &prep, t).unwrap();
        assert!(certified::verify(&s, &c, &codec, &h, &cert, 8));
        assert!(!certified::verify(&s, &c, &codec, &honest, &cert, 8));
        let mut incomplete = cert.clone();
        if let Evidence::Semantic { fields, .. } = &mut incomplete.evidence {
            fields.clear();
        }
        assert!(!certified::verify(&s, &c, &codec, &h, &incomplete, 8));
        let mut corrupted = cert;
        if let Evidence::Semantic { fields, .. } = &mut corrupted.evidence {
            fields[0].fragment.data[0] ^= 1;
        }
        assert!(!certified::verify(&s, &c, &codec, &h, &corrupted, 8));
    }
    assert!(module_seen);
}

#[test]
fn generated_incremental_recovery_counts_inputs_once_and_binds_opening_range() {
    let s = setup(&[3; 4], 4);
    let c = context(&s);
    let o = opening();
    let codec = codec(&s);
    let (p, shares) = ax::generate(&s, &c, &o).unwrap();
    let file = codec.commit_file(p.encode()).unwrap();
    let h = Header::new(&s, &c, file.root());
    let mut cache = wiawvss::IncrementalRecovery::new(&s, &c, file).unwrap();
    let mut bad = shares[1].clone();
    bad.token[0] ^= 1;
    for _ in 0..3 {
        assert!(
            cache
                .recover(&s, &c, &codec, &h, [&shares[0], &bad, &shares[0]], 8)
                .unwrap()
                .is_none()
        );
    }
    assert_eq!(cache.token_checks, 2);
    assert_eq!(cache.weight, 3u8.into());
    let cert = cache
        .recover(&s, &c, &codec, &h, [&shares[1]], 8)
        .unwrap()
        .unwrap();
    assert!(matches!(&cert.evidence,Evidence::Success(x) if x==&o));
    assert!(certified::verify(&s, &c, &codec, &h, &cert, 8));
    assert!(!certified::verify(&s, &c, &codec, &h, &cert, 4));
    assert!(cache.recover(&s, &c, &codec, &h, &shares, 4).is_err());
    let mut cross = h.clone();
    cross.root[0] ^= 1;
    assert!(cache.recover(&s, &c, &codec, &cross, &shares, 8).is_err());
}

#[test]
fn frozen_aptos_graphs_and_actual_serialized_css_sizes_match_the_clean_budget() {
    #[derive(serde::Deserialize)]
    struct Case {
        n: usize,
        weights: Vec<String>,
        threshold: String,
        gates: usize,
        or_gates: usize,
        warm_bytes: usize,
        full_wire_bytes: usize,
        boundary_bytes: usize,
        boundary_digests: usize,
    }
    let cases: Vec<Case> = serde_json::from_str(include_str!("fixtures/clean-aptos.json")).unwrap();
    for case in cases {
        let s = Setup::new_clean(
            Policy::from_strings(&case.weights, &case.threshold).unwrap(),
            Limits::default(),
        )
        .unwrap();
        assert_eq!(s.circuit().gates().len(), case.gates);
        assert_eq!(s.correction_blocks(), case.or_gates);
        let c = context(&s);
        let o = opening();
        let (full, shares) = ax::generate(&s, &c, &o).unwrap();
        let (small, other) = compact::generate(&s, &c, &o).unwrap();
        assert_eq!(shares, other);
        assert_eq!(200 + wcss::Public::encoded_len(&s), case.full_wire_bytes);
        assert_eq!(
            s.pvr_wire_count() - s.circuit().base(),
            case.boundary_digests
        );
        assert_eq!(full.encode().len(), case.boundary_bytes);
        assert_eq!(small.encode().len(), case.warm_bytes);
        let mut selected = vec![];
        for share in shares {
            selected.push(share);
            if s.circuit()
                .policy()
                .authorized(selected.iter().map(|x| x.party))
                .unwrap()
            {
                break;
            }
        }
        assert_eq!(
            compact::reconstruct(&s, &c, &small, &selected)
                .unwrap()
                .opening,
            o
        );
        assert!(
            matches!(terminal::recover(&s,&c,&full,&selected).unwrap(),Terminal::Success(x) if x==o)
        );
        println!(
            "Aptos{}: gates={}, OR={}, compact={} B, boundary PVR={} B (full-wire={} B)",
            case.n,
            case.gates,
            case.or_gates,
            case.warm_bytes,
            case.boundary_bytes,
            case.full_wire_bytes
        );
    }
}

#[test]
fn public_only_ax_and_prepared_gate_evaluation_preserve_all_legacy_bytes() {
    for profile in [
        wcss::CssProfile::Legacy,
        wcss::CssProfile::OptimizedV1,
        wcss::CssProfile::CleanV1,
    ] {
        for (weights, t) in [
            (vec![1u64], 1u64),
            (vec![3; 4], 4),
            (vec![2, 3, 7, 11, 17], 14),
        ] {
            let s = profile
                .setup(
                    Policy::new(weights.into_iter().map(Into::into).collect(), t.into()).unwrap(),
                    Limits::default(),
                )
                .unwrap();
            let c = context(&s);
            let o = opening();
            assert_eq!(
                ax::generate(&s, &c, &o).unwrap().0.encode(),
                ax::generate_public(&s, &c, &o).unwrap().encode()
            );
            assert_eq!(
                compact::generate(&s, &c, &o).unwrap().0.encode(),
                compact::generate_public(&s, &c, &o).unwrap().encode()
            );
            let (public, _) = wcss::share(&s, &c.id(), &[19; 32], &[23; 32]);
            assert_eq!(
                public.encode(),
                wcss::share_public(&s, &c.id(), &[19; 32], &[23; 32]).encode()
            );
            let mut prepared = wcss::GateEvaluator::new(&s, &c.id());
            for index in 0..=s.circuit().gates().len() {
                for branches in 0..=7 {
                    for tokens in [
                        [[0; 32]; 2],
                        [[5; 32], [0; 32]],
                        [[0; 32], [8; 32]],
                        [[5; 32], [8; 32]],
                    ] {
                        assert_eq!(
                            wcss::evaluate_gate(&s, &c.id(), index, branches, &tokens, |j| public
                                .correction(j)),
                            prepared.evaluate(index, branches, &tokens, |j| public.correction(j))
                        );
                    }
                }
            }
        }
    }
}
