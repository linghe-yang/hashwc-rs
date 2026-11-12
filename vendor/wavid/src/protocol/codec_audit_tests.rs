use super::*;
use types::Weight;

fn codec(n: usize, len: usize, b: usize) -> Codec {
    let m = WeightedMembership::new(vec![Weight::from(3); n], Weight::from(n as u64)).unwrap();
    Codec::with_params(
        &m,
        InstanceId::new(3, Some(0), 0),
        [7; 32],
        len,
        CodingParams { block_bytes: b },
    )
    .unwrap()
}

#[test]
fn arithmetic_frontier_length_matches_canonical_tree_for_every_small_interval() {
    let mut checked = 0;
    for m in 1..=96 {
        for start in 0..m {
            for len in 1..=m - start {
                assert_eq!(
                    frontier_len(m, start, len),
                    crypto::weighted_merkle::range_frontier(m, start, len).map(|f| f.len())
                );
                checked += 1;
            }
        }
    }
    for m in [127, 128, 129, 255, 256, 257, 4095, 4096, 4097, 1 << 24] {
        for start in [0, m / 2, m - 1] {
            for len in [1, 2, 7, 31].into_iter().filter(|&len| start + len <= m) {
                assert_eq!(
                    frontier_len(m, start, len),
                    crypto::weighted_merkle::range_frontier(m, start, len).map(|f| f.len())
                );
            }
        }
    }
    for (m, start, len) in [
        (0, 0, 1),
        (4, 0, 0),
        (4, 4, 1),
        (4, usize::MAX, 2),
        ((1 << 24) + 1, 0, 1),
    ] {
        assert_eq!(frontier_len(m, start, len), None);
    }
    assert_eq!(checked, 152096);
}

// Reference storage verifier uses the previous owned v3 deserialization.
fn owned_reference(c: &Codec, owner: usize, raw: &[u8], expected: Option<Hash>) -> Option<Hash> {
    if owner >= c.k || raw.len() != c.bundle_bytes(owner) {
        return None;
    }
    let p: PackedBundle = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(raw.len() as u64)
        .reject_trailing_bytes()
        .deserialize(raw)
        .ok()?;
    if p.version != 3 || p.directory.len() != c.q || p.stripes.len() != c.q {
        return None;
    }
    let root = IndexedTree::new(c.directory_context, &p.directory).root();
    if expected.is_some_and(|r| r != root) {
        return None;
    }
    for (z, s) in p.stripes.iter().enumerate() {
        if s.data.len() != c.counts[owner] * c.parameters.block_bytes {
            return None;
        }
        let blocks = s
            .data
            .chunks_exact(c.parameters.block_bytes)
            .collect::<Vec<_>>();
        verify_range(
            c.stripe_context(z),
            p.directory[z],
            c.m,
            c.positions[owner].start,
            &blocks,
            &s.siblings,
        )?;
    }
    Some(root)
}

#[test]
fn borrowed_storage_verification_agrees_with_owned_reference_on_corrupt_packets() {
    for (n, len, b) in [(4, 273, 32), (7, 901, 34), (4, 0, 128)] {
        let c = codec(n, len, b);
        let bytes = (0..len).map(|i| (i % 251) as u8).collect::<Vec<_>>();
        let prepared = c.prepare(&bytes).unwrap();
        for owner in 0..n {
            let raw = c.encode_bundle(owner, &prepared.bundles[owner]).unwrap();
            for root in [None, Some(prepared.root), Some([0; 32])] {
                assert_eq!(
                    c.verify_packet(owner, &raw, root),
                    owned_reference(&c, owner, &raw, root)
                );
            }
            assert_eq!(
                c.verify_packet(owner, &raw, Some(prepared.root)),
                Some(prepared.root)
            );
            for pos in 0..raw.len() {
                let mut bad = raw.clone();
                bad[pos] ^= 1;
                assert_eq!(
                    c.verify_packet(owner, &bad, Some(prepared.root)),
                    owned_reference(&c, owner, &bad, Some(prepared.root))
                );
                assert!(c.verify_packet(owner, &bad, Some(prepared.root)).is_none());
            }
            for end in 0..raw.len() {
                assert!(
                    c.verify_packet(owner, &raw[..end], Some(prepared.root))
                        .is_none()
                );
            }
            let mut extra = raw.clone();
            extra.push(0);
            assert!(
                c.verify_packet(owner, &extra, Some(prepared.root))
                    .is_none()
            );
            for offset in [
                1,
                c.directory_bytes(),
                c.directory_bytes() + 8 + c.counts[owner] * b,
            ] {
                let mut bad = raw.clone();
                bad[offset..offset + 8].fill(255);
                assert!(c.verify_packet(owner, &bad, Some(prepared.root)).is_none());
            }
        }
    }
}

#[test]
fn streaming_fragments_retain_authenticated_bytes_without_a_second_payload_copy() {
    let c = codec(4, 271, 32);
    let bytes = (0..271).map(|i| (i % 251) as u8).collect::<Vec<_>>();
    let p = c.prepare(&bytes).unwrap();
    let raw = c.encode_bundle(1, &p.bundles[1]).unwrap();
    for z in 0..c.q {
        let begin = c.directory_bytes() + z * c.stripe_bytes(1);
        let packet = raw[begin..begin + c.stripe_bytes(1)].to_vec();
        let pointer = packet.as_ptr();
        let fragments = c
            .decode_stripe_packet(1, z, packet, p.stripes[z].root())
            .unwrap();
        for (j, f) in fragments.iter().enumerate() {
            assert_eq!(f.data.as_ptr(), pointer);
            assert!(Arc::ptr_eq(&f.data, &fragments[0].data));
            let old = &p.bundles[1].stripes[z][j];
            assert_eq!(f.data(), old.data);
            let exported = f.export();
            assert!(verify(
                c.stripe_context(z),
                p.stripes[z].root(),
                c.m,
                exported.index,
                &exported.data,
                &exported.proof
            ));
        }
    }
}
