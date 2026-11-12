//! Same RS fields and matrix construction as reed-solomon-erasure 4.0.2.
//! Only multiplication of whole slices is specialized. CPU dispatch is local:
//! no native build flags, new coding parameters, or wire-format changes.
use reed_solomon_erasure::{Field, galois_8 as gf8, galois_16 as gf16};

pub(super) struct Gf8;
pub(super) struct Gf16;

// Delegate every scalar operation, including element enumeration, to the
// reference field. This preserves Vandermonde and inverse matrices exactly.
macro_rules! field {
    ($name:ident, $reference:ty, $elem:ty, $slice:ident) => {
        impl Field for $name {
            const ORDER: usize = <$reference>::ORDER;
            type Elem = $elem;
            fn add(a: $elem, b: $elem) -> $elem {
                <$reference>::add(a, b)
            }
            fn mul(a: $elem, b: $elem) -> $elem {
                <$reference>::mul(a, b)
            }
            fn div(a: $elem, b: $elem) -> $elem {
                <$reference>::div(a, b)
            }
            fn exp(a: $elem, n: usize) -> $elem {
                <$reference>::exp(a, n)
            }
            fn zero() -> $elem {
                <$reference>::zero()
            }
            fn one() -> $elem {
                <$reference>::one()
            }
            fn nth_internal(n: usize) -> $elem {
                <$reference>::nth_internal(n)
            }
            fn mul_slice(c: $elem, input: &[$elem], out: &mut [$elem]) {
                $slice::<false>(c, input, out);
            }
            fn mul_slice_add(c: $elem, input: &[$elem], out: &mut [$elem]) {
                $slice::<true>(c, input, out);
            }
        }
    };
}
field!(Gf8, gf8::Field, u8, slice8);
field!(Gf16, gf16::Field, [u8; 2], slice16);

fn slice8<const ADD: bool>(c: u8, input: &[u8], out: &mut [u8]) {
    assert_eq!(input.len(), out.len());
    #[cfg(target_arch = "x86_64")]
    if input.len() >= 32 && std::is_x86_feature_detected!("avx2") {
        // SAFETY: runtime feature detection precedes every AVX2 entry. Equal
        // slice lengths were checked; the kernel bounds every unaligned access.
        unsafe { x86::slice8::<ADD>(c, input, out) };
        return;
    }
    scalar8::<ADD>(c, input, out);
}

fn scalar8<const ADD: bool>(c: u8, input: &[u8], out: &mut [u8]) {
    if ADD {
        gf8::Field::mul_slice_add(c, input, out);
    } else {
        gf8::Field::mul_slice(c, input, out);
    }
}

fn slice16<const ADD: bool>(c: [u8; 2], input: &[[u8; 2]], out: &mut [[u8; 2]]) {
    assert_eq!(input.len(), out.len());
    #[cfg(target_arch = "x86_64")]
    if input.len() >= 16 && std::is_x86_feature_detected!("avx2") {
        // SAFETY: same runtime guard and length contract as slice8. Arrays of
        // two u8 have size two and alignment one; their byte order is unchanged.
        unsafe { x86::slice16::<ADD>(c, input, out) };
        return;
    }
    scalar16::<ADD>(c, input, out);
}

// In the reference GF((2^8)^2), X^2 = 2X + 128, and [a,b] represents aX+b.
// (aX+b)(xX+y) = ((b+2a)x+ay)X + (128ax+by).
// Precompute the two public coefficients once per slice, rather than reducing
// the extension polynomial for every element. This also accelerates fallback.
fn coefficients16(c: [u8; 2]) -> [u8; 4] {
    [c[1] ^ gf8::mul(2, c[0]), c[0], gf8::mul(128, c[0]), c[1]]
}

fn scalar16<const ADD: bool>(c: [u8; 2], input: &[[u8; 2]], out: &mut [[u8; 2]]) {
    assert_eq!(input.len(), out.len());
    let [a, b, c, d] = coefficients16(c).map(|x| &gf8::MUL_TABLE[x as usize]);
    for (x, y) in input.iter().zip(out) {
        let hi = a[x[0] as usize] ^ b[x[1] as usize];
        let lo = c[x[0] as usize] ^ d[x[1] as usize];
        if ADD {
            y[0] ^= hi;
            y[1] ^= lo;
        } else {
            *y = [hi, lo];
        }
    }
}

#[cfg(target_arch = "x86_64")]
mod x86 {
    use super::*;
    use std::{arch::x86_64::*, sync::OnceLock};

    // GF(2^8) multiplication is F_2-linear: c*x = c*(x&15) + c*(x&240).
    // Tables depend only on public field coefficients. They are built from the
    // pinned reference table once (8 KiB), not per file, stripe, or party.
    fn tables() -> &'static [[[u8; 16]; 2]; 256] {
        static TABLES: OnceLock<[[[u8; 16]; 2]; 256]> = OnceLock::new();
        TABLES.get_or_init(|| {
            std::array::from_fn(|c| {
                [
                    std::array::from_fn(|i| gf8::MUL_TABLE[c][i]),
                    std::array::from_fn(|i| gf8::MUL_TABLE[c][i << 4]),
                ]
            })
        })
    }

    struct Lookup(__m256i, __m256i);

    #[target_feature(enable = "avx2")]
    unsafe fn lookup(c: u8) -> Lookup {
        let t = &tables()[c as usize];
        // SAFETY: each lookup row holds exactly 16 initialized bytes; unaligned
        // loads are allowed. Both AVX2 lanes receive the same 16-entry table.
        unsafe {
            Lookup(
                _mm256_broadcastsi128_si256(_mm_loadu_si128(t[0].as_ptr().cast())),
                _mm256_broadcastsi128_si256(_mm_loadu_si128(t[1].as_ptr().cast())),
            )
        }
    }

    #[target_feature(enable = "avx2")]
    unsafe fn product(x: __m256i, t: &Lookup) -> __m256i {
        let mask = _mm256_set1_epi8(15);
        let lo = _mm256_and_si256(x, mask);
        let hi = _mm256_and_si256(_mm256_srli_epi16::<4>(x), mask);
        _mm256_xor_si256(_mm256_shuffle_epi8(t.0, lo), _mm256_shuffle_epi8(t.1, hi))
    }

    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn slice8<const ADD: bool>(c: u8, input: &[u8], out: &mut [u8]) {
        assert_eq!(input.len(), out.len());
        // SAFETY: caller checked AVX2. A vector access is made only when 32
        // bytes remain in both disjoint slices. The scalar tail handles the rest.
        unsafe {
            let t = lookup(c);
            let mut i = 0;
            while input.len() - i >= 32 {
                let x = _mm256_loadu_si256(input.as_ptr().add(i).cast());
                let mut y = product(x, &t);
                if ADD {
                    y = _mm256_xor_si256(y, _mm256_loadu_si256(out.as_ptr().add(i).cast()));
                }
                _mm256_storeu_si256(out.as_mut_ptr().add(i).cast(), y);
                i += 32;
            }
            scalar8::<ADD>(c, &input[i..], &mut out[i..]);
        }
    }

    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn slice16<const ADD: bool>(
        c: [u8; 2],
        input: &[[u8; 2]],
        out: &mut [[u8; 2]],
    ) {
        assert_eq!(input.len(), out.len());
        // SAFETY: 16 two-byte elements fit each 32-byte access. No byte casts
        // escape this function; initialized input and output slices are disjoint.
        unsafe {
            let [a, b, c0, d] = coefficients16(c).map(|c| lookup(c));
            let mask = _mm256_set1_epi16(255);
            let mut i = 0;
            while input.len() - i >= 16 {
                let x = _mm256_loadu_si256(input.as_ptr().add(i).cast());
                let hi = _mm256_and_si256(x, mask);
                let lo = _mm256_srli_epi16::<8>(x);
                let yhi = _mm256_xor_si256(product(hi, &a), product(lo, &b));
                let ylo = _mm256_xor_si256(product(hi, &c0), product(lo, &d));
                let mut y = _mm256_xor_si256(yhi, _mm256_slli_epi16::<8>(ylo));
                if ADD {
                    y = _mm256_xor_si256(y, _mm256_loadu_si256(out.as_ptr().add(i).cast()));
                }
                _mm256_storeu_si256(out.as_mut_ptr().add(i).cast(), y);
                i += 16;
            }
            scalar16::<ADD>(c, &input[i..], &mut out[i..]);
        }
    }
}

#[cfg(test)]
#[path = "rs_field_tests.rs"]
mod tests;
