use std::collections::BTreeMap;
use types::{InstanceId, Weight, WeightedMembership};
use wavid::{Codec, CodingParams, Retrieval, StorageFault};

fn codec(n: usize, bytes: usize, block_bytes: usize) -> Codec {
    let m = WeightedMembership::new(vec![Weight::from(3); n], Weight::from(n as u64)).unwrap();
    Codec::with_params(
        &m,
        InstanceId::new(2, Some(0), 7),
        [19; 32],
        bytes,
        CodingParams { block_bytes },
    )
    .unwrap()
}
fn recover(codec: &Codec, prepared: &wavid::Prepared) -> Retrieval {
    let mut rows: Vec<_> = (0..codec.q).map(|_| BTreeMap::new()).collect();
    // Holder zero stays silent: reconstruct from other physical holders.
    for bundle in &prepared.bundles[1..] {
        for (z, fragments) in bundle.stripes.iter().enumerate() {
            for f in fragments {
                rows[z].insert(f.index, f.clone());
            }
        }
    }
    codec
        .recover(prepared.root, &prepared.bundles[0].directory, &rows)
        .unwrap()
        .unwrap()
}
#[test]
fn on_demand_openings_match_eager_proofs_for_every_layout_and_field() {
    for n in [4, 90] {
        // Exercise both GF8 and GF16.
        for b in [32, 34, 64, 128, 256, 4096] {
            let data: Vec<_> = (0..n * b + 37).map(|i| (i * 17) as u8).collect();
            let codec = codec(n, data.len(), b);
            let p = codec.prepare(&data).unwrap();
            let Retrieval::File(file) = recover(&codec, &p) else {
                panic!("honest code rejected")
            };
            assert_eq!(file, data);
            assert_eq!(file.root(), p.root);
            assert_eq!(file.parameters(), CodingParams { block_bytes: b });
            assert_eq!(file.coding_context(), codec.context);
            // Clones share the backing allocation (no full-file event/state copies).
            let clone = file.clone();
            assert_eq!(file.as_ptr(), clone.as_ptr());
            for block in [0, 1, n - 1, n, codec.q * codec.k - 1] {
                let lazy = file.open_source(block).unwrap();
                let eager = codec.source_opening(&p, block).unwrap();
                assert_eq!(
                    bincode::serialize(&lazy).unwrap(),
                    bincode::serialize(&eager).unwrap()
                );
                assert!(codec.verify_source(p.root, &lazy));
            }
            // A semantic field crossing both a block boundary and a stripe boundary.
            let openings = file.open_range(n * b - 3, 11).unwrap();
            assert_eq!(openings.len(), 2);
            for opening in &openings {
                assert!(codec.verify_source(p.root, opening));
            }
            let joined: Vec<_> = openings
                .iter()
                .flat_map(|o| o.fragment.data.clone())
                .collect();
            assert_eq!(&joined[b - 3..b + 8], &data[n * b - 3..n * b + 8]);
            assert!(file.open_range(data.len(), 0).unwrap().is_empty());
            assert!(file.open_range(data.len(), 1).is_err());
            assert!(file.open_range(usize::MAX, 1).is_err());
            assert!(file.open_source(codec.q * codec.k).is_err());
            let reopened = codec.validate_file(p.root, data.clone()).unwrap();
            assert_eq!(reopened, data);
            assert!(codec.validate_file([0; 32], data.clone()).is_err());
        }
    }
}
#[test]
fn parameters_are_validated_and_bound_into_commitments() {
    let m = WeightedMembership::new(vec![Weight::from(3); 4], Weight::from(4)).unwrap();
    for b in [0, 1, 31, 33, 4097, usize::MAX] {
        assert!(Codec::with_params(
            &m,
            InstanceId::new(0, Some(0), 0),
            [0; 32],
            1,
            CodingParams { block_bytes: b }
        )
        .is_err());
    }
    let a = codec(4, 200, 32);
    let b = codec(4, 200, 64);
    let pa = a.prepare(&vec![1; 200]).unwrap();
    let pb = b.prepare(&vec![1; 200]).unwrap();
    assert_ne!(pa.root, pb.root);
    assert!(!b.verify_source(pa.root, &a.source_opening(&pa, 0).unwrap()));
    let raw = a.encode_bundle(0, &pa.bundles[0]).unwrap();
    assert!(b.decode_bundle(0, &raw).is_none());
    let mut forged = a.source_opening(&pa, 0).unwrap();
    forged.fragment.index = a.k; // A parity coordinate is never a source opening.
    assert!(!a.verify_source(pa.root, &forged));
}
#[test]
fn coding_fault_keeps_original_authenticated_paths_and_padding_stays_public() {
    for b in [32, 256] {
        let c = codec(4, 1, b);
        let mut rows = c.prepare(&[7]).unwrap().rows;
        rows[0][c.m - 1][0] ^= 1;
        let bad = c.commit_rows(rows).unwrap();
        let Retrieval::Invalid(fault @ StorageFault::Coding(_)) = recover(&c, &bad) else {
            panic!("bad code delivered")
        };
        assert!(c.verify_fault(bad.root, &fault));
        if let StorageFault::Coding(w) = &fault {
            for fragment in &w.fragments {
                assert!(crypto::weighted_merkle::verify(
                    c.stripe_context(0),
                    w.root,
                    c.m,
                    fragment.index,
                    &fragment.data,
                    &fragment.proof
                ));
            }
        }
        // A valid codeword with nonzero out-of-file bytes must yield padding evidence.
        let full = codec(4, 4 * b, b).prepare(&vec![1; 4 * b]).unwrap();
        let padded = c.commit_rows(full.rows).unwrap();
        let Retrieval::Invalid(fault @ StorageFault::Padding(_)) = recover(&c, &padded) else {
            panic!("bad padding delivered")
        };
        assert!(c.verify_fault(padded.root, &fault));
    }
}
#[test]
fn empty_file_retains_a_valid_zero_source_opening() {
    let c = codec(4, 0, 128);
    let p = c.prepare(&[]).unwrap();
    let Retrieval::File(file) = recover(&c, &p) else {
        panic!()
    };
    assert!(file.is_empty());
    let opening = file.open_source(0).unwrap();
    assert!(c.verify_source(p.root, &opening));
    assert_eq!(opening.fragment.data, vec![0; 128]);
}
