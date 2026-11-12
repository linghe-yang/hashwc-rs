use super::*;
use reed_solomon_erasure::ReedSolomon;

#[test]
fn gf8_every_product_and_slice_boundary_matches_reference() {
    let lengths = [
        0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 255, 256, 257, 1031,
    ];
    let raw: Vec<u8> = (0..1040).map(|i| (i * 73 + 19) as u8).collect();
    for c in 0..=255 {
        for len in lengths {
            // Deliberately unaligned input and output, including both tails.
            let input = &raw[3..3 + len];
            let mut expected = vec![0x53; len];
            let mut scalar = vec![0x53; len];
            let mut auto = vec![0x53; len + 5];
            gf8::Field::mul_slice(c, input, &mut expected);
            scalar8::<false>(c, input, &mut scalar);
            Gf8::mul_slice(c, input, &mut auto[5..]);
            assert_eq!(scalar, expected);
            assert_eq!(&auto[5..], expected);
            assert_eq!(&auto[..5], &[0x53; 5]);
            expected.fill(0x53);
            scalar.fill(0x53);
            auto.fill(0x53);
            gf8::Field::mul_slice_add(c, input, &mut expected);
            scalar8::<true>(c, input, &mut scalar);
            Gf8::mul_slice_add(c, input, &mut auto[5..]);
            assert_eq!(scalar, expected);
            assert_eq!(&auto[5..], expected);
            assert_eq!(&auto[..5], &[0x53; 5]);
        }
    }
}

fn compare16(c: [u8; 2], input: &[[u8; 2]]) {
    let mut expected = vec![[0x53, 0xa7]; input.len()];
    let mut scalar = expected.clone();
    let mut auto = vec![[0x53, 0xa7]; input.len() + 3];
    gf16::Field::mul_slice(c, input, &mut expected);
    scalar16::<false>(c, input, &mut scalar);
    Gf16::mul_slice(c, input, &mut auto[3..]);
    assert_eq!(scalar, expected, "scalar coefficient {c:?}");
    assert_eq!(&auto[3..], expected, "auto coefficient {c:?}");
    assert_eq!(&auto[..3], &[[0x53, 0xa7]; 3]);
    expected.fill([0x53, 0xa7]);
    scalar.fill([0x53, 0xa7]);
    auto.fill([0x53, 0xa7]);
    gf16::Field::mul_slice_add(c, input, &mut expected);
    scalar16::<true>(c, input, &mut scalar);
    Gf16::mul_slice_add(c, input, &mut auto[3..]);
    assert_eq!(scalar, expected, "scalar add coefficient {c:?}");
    assert_eq!(&auto[3..], expected, "auto add coefficient {c:?}");
    assert_eq!(&auto[..3], &[[0x53, 0xa7]; 3]);
}

#[test]
fn gf16_every_coefficient_on_basis_and_both_vector_lanes_matches_reference() {
    let mut input: Vec<_> = (0..16).map(|bit| gf16::Field::nth(1 << bit)).collect();
    // Both lanes plus a scalar tail, with non-basis values after the first 16.
    input.extend((0..17).map(|i| [((i * 71) ^ 193) as u8, ((i * 43) ^ 51) as u8]));
    for c in 0..65536 {
        compare16(gf16::Field::nth(c), &input);
    }
}

#[test]
fn gf16_all_inputs_and_tail_boundaries_match_reference() {
    let raw: Vec<_> = (0..65536).map(gf16::Field::nth).collect();
    for c in [[0, 0], [0, 1], [1, 0], [1, 1], [128, 64], [255, 255]] {
        compare16(c, &raw);
        for len in [0, 1, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 513] {
            compare16(c, &raw[3..3 + len]);
        }
    }
}

// Exercise the scalar fallback for complete codes without changing process
// environment or disabling the host CPU. Public protocol configuration is fixed.
struct Scalar16;
field!(Scalar16, gf16::Field, [u8; 2], scalar16);

fn codes_agree<A: Field, B: Field<Elem = A::Elem>>(k: usize, m: usize, len: usize) {
    let a = ReedSolomon::<A>::new(k, m - k).unwrap();
    let b = ReedSolomon::<B>::new(k, m - k).unwrap();
    let source: Vec<Vec<_>> = (0..m)
        .map(|r| {
            (0..len)
                .map(|c| {
                    if r < k {
                        A::nth((r * 131 + c * 43 + 17) % A::ORDER)
                    } else {
                        A::zero()
                    }
                })
                .collect()
        })
        .collect();
    let mut ea = source.clone();
    let mut eb = source;
    a.encode(&mut ea).unwrap();
    b.encode(&mut eb).unwrap();
    assert_eq!(ea, eb);
    assert!(a.verify(&ea).unwrap());
    assert!(b.verify(&ea).unwrap());
    // Systematic, parity-first, and a noncontiguous deterministic subset. The
    // latter exercises a different inverse matrix and adversarial arrival order.
    for order in [0, 1, 2] {
        let mut indices: Vec<_> = (0..m).collect();
        if order == 1 {
            indices.reverse();
        }
        if order == 2 {
            indices.sort_by_key(|i| ((i * 47) % (m + 1), *i));
        }
        let mut sa: Vec<_> = (0..m).map(|_| None).collect();
        for &i in &indices[..k] {
            sa[i] = Some(ea[i].clone());
        }
        let mut sb = sa.clone();
        a.reconstruct_data(&mut sa).unwrap();
        b.reconstruct_data(&mut sb).unwrap();
        assert_eq!(sa, sb);
        for i in 0..k {
            assert_eq!(sa[i].as_ref().unwrap(), &ea[i]);
        }
        a.reconstruct(&mut sa).unwrap();
        b.reconstruct(&mut sb).unwrap();
        assert_eq!(sa, sb);
        for i in 0..m {
            assert_eq!(sa[i].as_ref().unwrap(), &ea[i]);
        }
    }
}

#[test]
fn rs_encode_and_recover_preserve_reference_codewords() {
    for (k, m, len) in [(4, 13, 1), (16, 55, 33), (60, 209, 129), (85, 255, 65)] {
        codes_agree::<gf8::Field, Gf8>(k, m, len);
    }
    for (k, m, len) in [(4, 13, 1), (85, 256, 17), (91, 273, 33), (100, 337, 65)] {
        codes_agree::<gf16::Field, Gf16>(k, m, len);
        codes_agree::<gf16::Field, Scalar16>(k, m, len);
    }
}

#[test]
#[should_panic]
fn gf8_rejects_unequal_lengths_before_simd() {
    Gf8::mul_slice(7, &[1; 64], &mut [0; 32]);
}

#[test]
#[should_panic]
fn gf16_rejects_unequal_lengths_before_simd() {
    Gf16::mul_slice_add([7, 11], &[[1; 2]; 32], &mut [[0; 2]; 16]);
}
