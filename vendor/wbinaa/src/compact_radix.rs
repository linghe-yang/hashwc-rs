//! Fixed-capacity arithmetic for at most 91 base-96 digits (< 2^637).
//! No machine-word restriction is imposed on stake weights; these are wire digits.
use super::MAX_PARTIES;
const WORDS: usize = 20;

pub(super) struct Number {
    words: [u32; WORDS],
    used: usize,
}
impl Number {
    pub fn zero() -> Self {
        Self {
            words: [0; WORDS],
            used: 0,
        }
    }
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut out = Self::zero();
        for (i, b) in bytes.iter().enumerate() {
            out.words[i / 4] |= (*b as u32) << (8 * (i % 4));
        }
        out.used = bytes.len().div_ceil(4);
        out.trim();
        out
    }
    pub fn mul_add(&mut self, base: u32, digit: u32) {
        let mut carry = digit as u64;
        for word in &mut self.words[..self.used] {
            let value = *word as u64 * base as u64 + carry;
            *word = value as u32;
            carry = value >> 32;
        }
        if carry != 0 {
            self.words[self.used] = carry as u32;
            self.used += 1;
        }
    }
    pub fn div_rem(&mut self, base: u32) -> u32 {
        let mut remainder = 0u64;
        for word in self.words[..self.used].iter_mut().rev() {
            let value = (remainder << 32) | *word as u64;
            *word = (value / base as u64) as u32;
            remainder = value % base as u64;
        }
        self.trim();
        remainder as u32
    }
    pub fn is_zero(&self) -> bool {
        self.used == 0
    }
    fn trim(&mut self) {
        while self.used > 0 && self.words[self.used - 1] == 0 {
            self.used -= 1;
        }
    }
    pub fn append(&self, out: &mut Vec<u8>, length: usize) {
        out.extend((0..length).map(|i| (self.words[i / 4] >> (8 * (i % 4))) as u8));
    }
}

// Exact byte lengths of base^n-1, precomputed at compile time, with no floats.
const fn lengths() -> [[u8; MAX_PARTIES + 1]; 97] {
    let mut table = [[0; MAX_PARTIES + 1]; 97];
    let mut base = 1u32;
    while base <= 96 {
        let mut words = [0u32; WORDS];
        words[0] = 1;
        let mut used = 1;
        let mut n = 1;
        while n <= MAX_PARTIES {
            let mut carry = 0u64;
            let mut i = 0;
            while i < used {
                let value = words[i] as u64 * base as u64 + carry;
                words[i] = value as u32;
                carry = value >> 32;
                i += 1;
            }
            if carry != 0 {
                words[used] = carry as u32;
                used += 1;
            }
            let bits = if base.is_power_of_two() {
                n * base.trailing_zeros() as usize
            } else {
                // A power of a non-power-of-two is never a power of two.
                32 * (used - 1) + 32 - words[used - 1].leading_zeros() as usize
            };
            table[base as usize][n] = bits.div_ceil(8) as u8;
            n += 1;
        }
        base += 1;
    }
    table
}
static LENGTHS: [[u8; MAX_PARTIES + 1]; 97] = lengths();

pub(super) fn byte_len(base: u32, n: usize) -> usize {
    LENGTHS[base as usize][n] as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;
    use num_traits::ToPrimitive;
    #[test]
    fn every_radix_length_and_fixed_arithmetic_match_unbounded_reference() {
        for base in 1u32..=96 {
            let mut capacity = BigUint::from(1u8);
            let mut reference = BigUint::from(0u8);
            let mut number = Number::zero();
            for n in 1..=MAX_PARTIES {
                capacity *= base;
                let length = (&capacity - BigUint::from(1u8)).bits().div_ceil(8);
                assert_eq!(byte_len(base, n), length);
                let digit = (17 * n as u32 + 3) % base;
                number.mul_add(base, digit);
                reference = reference * base + digit;
                let mut bytes = vec![];
                number.append(&mut bytes, length);
                assert_eq!(BigUint::from_bytes_le(&bytes), reference);
                let mut copy = Number::from_bytes(&bytes);
                let remainder = copy.div_rem(base);
                assert_eq!(remainder, (&reference % base).to_u32().unwrap());
                let mut quotient = vec![];
                copy.append(&mut quotient, length);
                assert_eq!(BigUint::from_bytes_le(&quotient), &reference / base);
            }
        }
    }
}
