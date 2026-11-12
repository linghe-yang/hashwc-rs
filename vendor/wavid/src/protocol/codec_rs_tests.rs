use super::*;
use types::Weight;

#[test]
fn both_fields_reject_committed_bad_codewords_and_nonzero_padding() {
    for n in [4, 86] {
        let membership =
            WeightedMembership::new(vec![Weight::from(3); n], Weight::from(n as u64)).unwrap();
        let b = 34; // vector plus a nonempty scalar tail in both fields
        let data: Vec<_> = (0..n * b + 5).map(|i| (i % 251) as u8).collect();
        let codec = Codec::with_params(
            &membership,
            InstanceId::new(9, Some(0), 0),
            [7; 32],
            data.len(),
            CodingParams { block_bytes: b },
        )
        .unwrap();
        assert_eq!(codec.m >= 256, n == 86);
        let good = codec.prepare(&data).unwrap();
        for changed in [0, codec.m - 1] {
            let mut rows = good.rows.clone();
            rows[0][changed][b - 1] ^= 0x87;
            let bad = codec.commit_rows(rows).unwrap();
            for start in [0, codec.m - codec.k] {
                let received = fragments(&codec, &bad, start);
                let directory: Vec<_> = bad.stripes.iter().map(IndexedTree::root).collect();
                let Some(Retrieval::Invalid(fault @ StorageFault::Coding(_))) =
                    codec.recover(bad.root, &directory, &received).unwrap()
                else {
                    panic!("committed malformed codeword accepted; n={n}, changed={changed}");
                };
                assert!(codec.verify_fault(bad.root, &fault));
                assert!(!codec.verify_fault(good.root, &fault));
                let StorageFault::Coding(mut forged) = fault else {
                    unreachable!()
                };
                forged.fragments[0].data[0] ^= 1;
                assert!(!codec.verify_fault(bad.root, &StorageFault::Coding(forged)));
            }
        }
        let mut rows = good.rows.clone();
        let z = codec.q - 1;
        let mut source = codec.source_stripe(&data, z);
        source[5] = 1;
        rows[z] = codec
            .encode_stripe(&source)
            .unwrap()
            .chunks_exact(b)
            .map(<[u8]>::to_vec)
            .collect();
        let bad = codec.commit_rows(rows).unwrap();
        let directory: Vec<_> = bad.stripes.iter().map(IndexedTree::root).collect();
        let received = fragments(&codec, &bad, codec.m - codec.k);
        let Some(Retrieval::Invalid(fault @ StorageFault::Padding(_))) =
            codec.recover(bad.root, &directory, &received).unwrap()
        else {
            panic!("nonzero padding accepted; n={n}");
        };
        assert!(codec.verify_fault(bad.root, &fault));
        assert!(!codec.verify_fault(good.root, &fault));
    }
}

fn fragments(codec: &Codec, prepared: &Prepared, start: usize) -> Vec<BTreeMap<usize, Fragment>> {
    prepared
        .rows
        .iter()
        .enumerate()
        .map(|(z, row)| {
            (start..start + codec.k)
                .map(|i| {
                    (
                        i,
                        Fragment {
                            index: i,
                            data: row[i].clone(),
                            proof: prepared.stripes[z].proof(i),
                        },
                    )
                })
                .collect()
        })
        .collect()
}
