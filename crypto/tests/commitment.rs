use crypto::*;
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
#[test]
fn python_hashlib_known_answers() {
    // Independently generated with Python hashlib.shake_256 and struct.pack('<Q', ...).
    assert_eq!(
        hex(&input_commitment(&[1; 32], 2, &[3; 32])),
        "09d3a311955044052bd7e9f6f333b8dbdbf9e589260d90ec0abe1bc86af0ebcf"
    );
    assert_eq!(
        hex(&expand(b"AX/derive", &[&[1; 32], &[2; 32], &[3; 32]], 128)),
        "584cc3e12974b6c5d600fd798da986fc9a94a7e2a2eac28b85fdfe19d267ba9407da554b2a1025176c2e9011335491d94ba353b1fa7f9b97b1a11d1cbb23b33b8a6e59cd26145d64b142620421e171e5a74d5757d8ea46bd221b5902bc8ae92db4f859a1a8af71ea80d381883eaedd5243f704d5cc5310134cd666e3ecfea1a6"
    );
}
#[test]
fn domains_indices_lengths_and_tuple_boundaries_are_distinct() {
    let context = [1; 32];
    let token = [2; 32];
    let input = input_commitment(&context, 0, &token);
    assert_ne!(input, wire_commitment(&context, 0, &token));
    assert_ne!(input, input_commitment(&context, 1, &token));
    assert_ne!(input, input_commitment(&[3; 32], 0, &token));
    assert_ne!(
        wire_commitment(&context, 0, &token),
        edge_pad(&context, 0, 0, 0, &token)
    );
    assert_ne!(hash(b"test", &[b"ab", b"c"]), hash(b"test", &[b"a", b"bc"]));
    assert_ne!(
        expand(b"test", &[b"a"], 32),
        expand(b"test", &[b"a"], 64)[..32]
    );
}

#[test]
fn streamed_tail_preserves_part_boundaries_and_empty_parts() {
    let bytes = (0..=255).collect::<Vec<u8>>();
    for size in [1, 7, 32, 63, 256] {
        assert_eq!(
            hash_with_tail(
                b"transcript",
                &[b"context", b"root"],
                bytes.len(),
                bytes.chunks(size)
            ),
            hash(b"transcript", &[b"context", b"root", &bytes])
        );
    }
    assert_eq!(
        hash_with_tail(b"empty", &[b""], 0, std::iter::empty()),
        hash(b"empty", &[b"", b""])
    );
    assert_ne!(
        hash_with_tail(b"empty", &[], 0, std::iter::empty()),
        hash(b"empty", &[])
    );
    let mut output = [0; 128];
    expand_into(b"AX/derive", &[&[1; 32], &[2; 32], &[3; 32]], &mut output);
    assert_eq!(
        output.as_slice(),
        expand(b"AX/derive", &[&[1; 32], &[2; 32], &[3; 32]], 128)
    );
}

#[test]
fn canonical_framing_matches_independent_reference_at_boundaries() {
    use sha3::{
        Shake256,
        digest::{ExtendableOutput, Update, XofReader},
    };
    fn reference(domain: &[u8], parts: &[&[u8]], len: usize) -> Vec<u8> {
        // Assemble the specification independently of either production path.
        let mut bytes = b"hashwc/v1\0".to_vec();
        bytes.extend_from_slice(&(domain.len() as u64).to_le_bytes());
        bytes.extend_from_slice(domain);
        bytes.extend_from_slice(&(len as u64).to_le_bytes());
        bytes.extend_from_slice(&(parts.len() as u64).to_le_bytes());
        for part in parts {
            bytes.extend_from_slice(&(part.len() as u64).to_le_bytes());
            bytes.extend_from_slice(part);
        }
        let mut h = Shake256::default();
        h.update(&bytes);
        let mut output = vec![0; len];
        h.finalize_xof().read(&mut output);
        output
    }
    for domain_len in [0, 4, 135, 136, 137, 255, 256, 257, 1024] {
        let domain = vec![0x71; domain_len];
        // Dense lengths cross the SHAKE rate and prepared-frame capacity.
        for part_len in 0..=300 {
            let data = (0..part_len).map(|i| (i * 37) as u8).collect::<Vec<_>>();
            for parts in [
                vec![],
                vec![data.as_slice()],
                vec![b"", data.as_slice(), b""],
            ] {
                for output_len in [0, 1, 32, 136, 137] {
                    assert_eq!(
                        expand(&domain, &parts, output_len),
                        reference(&domain, &parts, output_len),
                        "domain={domain_len}, part={part_len}, parts={}, output={output_len}",
                        parts.len()
                    );
                }
            }
        }
    }
}

#[test]
fn prepared_hash_reuses_only_framing_and_binds_every_variable_part() {
    for domain in [
        b"wire".as_slice(),
        b"css/generated-and/v1",
        b"css/generated-or/v1",
    ] {
        for context_byte in [0, 1, 255] {
            let context = [context_byte; 32];
            let fixed = [context.as_slice()];
            let mut template = HashTemplate::<256, 3>::new(domain, &fixed, [8, 32, 32]).unwrap();
            for wire in [0u64, 1, 63, 64, 255, u64::MAX] {
                for byte in [0u8, 7, 255] {
                    let id = wire.to_le_bytes();
                    let left = [byte; 32];
                    let right = [byte.wrapping_add(1); 32];
                    assert_eq!(
                        template.hash([&id, &left, &right]),
                        hash(domain, &[&context, &id, &left, &right])
                    );
                    // Reusing a template must not reuse any prior secret input.
                    assert_eq!(
                        template.hash([&id, &right, &left]),
                        hash(domain, &[&context, &id, &right, &left])
                    );
                }
            }
        }
    }
    // Exact capacity and overflow behavior; also cover empty fixed/variable parts.
    let mut full = HashTemplate::<256, 1>::new(b"", &[], [214]).unwrap();
    assert_eq!(full.hash([&[1; 214]]), hash(b"", &[&[1; 214]]));
    assert!(HashTemplate::<256, 1>::new(b"", &[], [215]).is_none());
    assert!(HashTemplate::<256, 1>::new(b"", &[], [usize::MAX]).is_none());
    assert!(HashTemplate::<0, 0>::new(b"", &[], []).is_none());
    assert_eq!(
        HashTemplate::<256, 0>::new(b"", &[], []).unwrap().hash([]),
        hash(b"", &[])
    );
    assert_eq!(
        HashTemplate::<256, 2>::new(b"", &[b""], [0, 0])
            .unwrap()
            .hash([b"", b""]),
        hash(b"", &[b"", b"", b""])
    );
    let mut or_hash =
        HashTemplate::<256, 3>::new(b"css/generated-or/v1", &[&[2; 32]], [8, 1, 32]).unwrap();
    for wire in [1u64, 512, u64::MAX] {
        for branch in [0, 1] {
            assert_eq!(
                or_hash.hash([&wire.to_le_bytes(), &[branch], &[3; 32]]),
                hash(
                    b"css/generated-or/v1",
                    &[&[2; 32], &wire.to_le_bytes(), &[branch], &[3; 32]]
                )
            );
        }
    }
}

#[test]
#[should_panic(expected = "fixed canonical part length")]
fn prepared_hash_rejects_wrong_length_instead_of_using_stale_bytes() {
    let mut template = HashTemplate::<256, 1>::new(b"test", &[], [32]).unwrap();
    template.hash([&[7; 31]]);
}
