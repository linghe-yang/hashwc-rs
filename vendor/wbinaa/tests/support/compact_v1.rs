//! Stateless, canonical wire encoding for at most 91 physical coordinates.
//! Only already-ready updates are encoded; no timers or cross-coordinate barrier.
use wbinaa::{Entry, ProtMsg, MAX_ROUNDS};
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use serde::{
    de::{Error as _, SeqAccess, Visitor},
    ser::SerializeTuple,
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::fmt;
use types::InstanceId;

pub const MAX_PARTIES: usize = 91;
// Two canonical u64 varints, a 12-bit round + 4-bit mode, and <=78 body bytes.
pub const MAX_ENCODED_BYTES: usize = 100;
const DENSE: u16 = 13;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactMsg(pub ProtMsg);

fn role(code: u8) -> usize {
    if code < 5 {
        0
    } else if code < 8 {
        1
    } else {
        2
    }
}
fn normalized(msg: &ProtMsg) -> Result<Vec<Entry>, String> {
    if msg.instance.dealer.is_some()
        || msg.round == 0
        || msg.round > MAX_ROUNDS
        || msg.entries.is_empty()
        || msg.entries.len() > 3 * MAX_PARTIES
    {
        return Err("compact BinAA header/entry limit".into());
    }
    let mut entries = msg.entries.clone();
    entries.sort_by_key(|e| (e.coordinate, e.code));
    let mut previous = None;
    for e in &entries {
        if e.coordinate as usize >= MAX_PARTIES
            || e.code > 10
            || (msg.round == 1 && e.code < 5 && e.code != 2 && e.code != 3)
        {
            return Err("compact BinAA coordinate/code".into());
        }
        let key = (e.coordinate, role(e.code));
        if previous == Some(key) {
            return Err("duplicate BinAA coordinate/role".into());
        }
        previous = Some(key);
    }
    Ok(entries)
}
fn varint(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let byte = (value & 127) as u8;
        value >>= 7;
        out.push(byte | if value != 0 { 128 } else { 0 });
        if value == 0 {
            break;
        }
    }
}
fn palettes(mask: u16) -> [Vec<u8>; 3] {
    let mut out: [Vec<u8>; 3] = Default::default();
    for code in 0..11 {
        if mask & (1 << code) != 0 {
            out[role(code)].push(code);
        }
    }
    out
}
fn radices(palette: &[Vec<u8>; 3], full: u8) -> Result<[u32; 3], String> {
    let mut bases = [0; 3];
    for r in 0..3 {
        let filled = full & (1 << r) != 0;
        if filled && palette[r].is_empty() {
            return Err("empty full role".into());
        }
        bases[r] = palette[r].len() as u32 + u32::from(!filled);
    }
    Ok(bases)
}
fn dense_bytes(base: u32, n: usize) -> usize {
    if base.is_power_of_two() {
        return (n * base.trailing_zeros() as usize).div_ceil(8);
    }
    let mut capacity = BigUint::from(1u8);
    for _ in 0..n {
        capacity *= base;
    }
    (capacity - BigUint::from(1u8)).bits().div_ceil(8)
}
fn dense(entries: &[Entry]) -> Vec<u8> {
    let n = entries.last().unwrap().coordinate as usize + 1;
    let mut slots = [[None; 3]; MAX_PARTIES];
    let mut mask = 0u16;
    for e in entries {
        slots[e.coordinate as usize][role(e.code)] = Some(e.code);
        mask |= 1 << e.code;
    }
    let palette = palettes(mask);
    let mut full = 0u8;
    for r in 0..3 {
        if slots[..n].iter().all(|s| s[r].is_some()) {
            full |= 1 << r;
        }
    }
    let bases = radices(&palette, full).expect("nonempty observed palette");
    let base: u32 = bases.iter().product();
    let mut digits = Vec::with_capacity(n);
    for slot in &slots[..n] {
        let mut digit = 0;
        let mut multiplier = 1;
        for r in 0..3 {
            let d = slot[r].map_or(0, |code| {
                palette[r].iter().position(|&v| v == code).unwrap() as u32
                    + u32::from(full & (1 << r) == 0)
            });
            digit += multiplier * d;
            multiplier *= bases[r];
        }
        digits.push(digit);
    }
    let metadata = (n as u32 - 1) | ((mask as u32) << 7) | ((full as u32) << 18);
    let mut out = metadata.to_le_bytes()[..3].to_vec();
    let length = dense_bytes(base, n);
    let bytes = if base.is_power_of_two() {
        let bits = base.trailing_zeros() as usize;
        let mut bytes = vec![0; length];
        for (i, digit) in digits.iter().enumerate() {
            for bit in 0..bits {
                if digit & (1 << bit) != 0 {
                    let p = i * bits + bit;
                    bytes[p / 8] |= 1 << (p % 8);
                }
            }
        }
        bytes
    } else {
        let mut number = BigUint::from(0u8);
        for digit in digits.iter().rev() {
            number = number * base + *digit;
        }
        let mut bytes = number.to_bytes_le();
        bytes.resize(length, 0);
        bytes
    };
    out.extend(bytes);
    out
}
fn sparse(entries: &[Entry]) -> Option<(u16, Vec<u8>)> {
    let k = entries.len();
    if k > 256 {
        return None;
    }
    let mode = if k <= 12 { k as u16 - 1 } else { 12 };
    let prefix = usize::from(k > 12);
    let mut out = vec![0u8; prefix + (10 * k).div_ceil(8)];
    if prefix != 0 {
        out[0] = (k - 1) as u8;
    }
    for (i, e) in entries.iter().enumerate() {
        let token = e.coordinate as u16 * 11 + e.code as u16;
        for bit in 0..10 {
            if token & (1 << bit) != 0 {
                let position = i * 10 + bit;
                out[prefix + position / 8] |= 1 << (position % 8);
            }
        }
    }
    Some((mode, out))
}
impl CompactMsg {
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let entries = normalized(&self.0)?;
        let dense = dense(&entries);
        let (mode, body) = match sparse(&entries) {
            Some((mode, sparse)) if sparse.len() <= dense.len() => (mode, sparse),
            _ => (DENSE, dense),
        };
        let mut out = Vec::with_capacity(22 + body.len());
        varint(self.0.instance.epoch, &mut out);
        varint(self.0.instance.slot, &mut out);
        out.extend_from_slice(&((mode << 12) | (self.0.round as u16 - 1)).to_le_bytes());
        out.extend(body);
        debug_assert!(out.len() <= MAX_ENCODED_BYTES);
        Ok(out)
    }
    pub fn decode(raw: &[u8]) -> Result<Self, String> {
        let mut position = 0;
        let out = read(|| {
            let byte = raw
                .get(position)
                .copied()
                .ok_or("truncated compact BinAA")?;
            position += 1;
            Ok(byte)
        })?;
        if position != raw.len() {
            return Err("trailing compact BinAA bytes".into());
        }
        Ok(out)
    }
}
fn read(mut input: impl FnMut() -> Result<u8, String>) -> Result<CompactMsg, String> {
    let mut raw = Vec::with_capacity(MAX_ENCODED_BYTES);
    let mut byte = || {
        if raw.len() >= MAX_ENCODED_BYTES {
            return Err("compact BinAA byte limit".into());
        }
        let b = input()?;
        raw.push(b);
        Ok(b)
    };
    fn integer(byte: &mut impl FnMut() -> Result<u8, String>) -> Result<u64, String> {
        let mut value = 0u64;
        for j in 0..10 {
            let b = byte()?;
            if j == 9 && b > 1 {
                return Err("u64 varint overflow".into());
            }
            value |= ((b & 127) as u64) << (7 * j);
            if b < 128 {
                return Ok(value);
            }
        }
        Err("unterminated varint".into())
    }
    let epoch = integer(&mut byte)?;
    let slot = integer(&mut byte)?;
    let header = u16::from_le_bytes([byte()?, byte()?]);
    let round = (header & 4095) as u32 + 1;
    let mode = header >> 12;
    let mut entries = vec![];
    if mode < DENSE {
        let k = if mode < 12 {
            mode as usize + 1
        } else {
            byte()? as usize + 1
        };
        if k > 61 {
            return Err("nonminimal sparse BinAA length".into());
        }
        let bytes: Vec<_> = (0..(10 * k).div_ceil(8))
            .map(|_| byte())
            .collect::<Result<_, _>>()?;
        for i in 0..k {
            let mut token = 0u16;
            for bit in 0..10 {
                let position = i * 10 + bit;
                token |= (((bytes[position / 8] >> (position % 8)) & 1) as u16) << bit;
            }
            if token >= 11 * MAX_PARTIES as u16 {
                return Err("invalid packed token".into());
            }
            entries.push(Entry {
                coordinate: (token / 11) as u32,
                code: (token % 11) as u8,
            });
        }
    } else if mode == DENSE {
        let metadata = u32::from_le_bytes([byte()?, byte()?, byte()?, 0]);
        if metadata >> 21 != 0 {
            return Err("nonzero dense padding".into());
        }
        let n = (metadata as usize & 127) + 1;
        if n > MAX_PARTIES {
            return Err("dense BinAA width".into());
        }
        let mask = ((metadata >> 7) & 2047) as u16;
        let full = ((metadata >> 18) & 7) as u8;
        let palette = palettes(mask);
        let bases = radices(&palette, full)?;
        let base: u32 = bases.iter().product();
        let length = dense_bytes(base, n);
        let bytes: Vec<_> = (0..length).map(|_| byte()).collect::<Result<_, _>>()?;
        let mut number = BigUint::from_bytes_le(&bytes);
        for coordinate in 0..n {
            let mut digit = if base.is_power_of_two() {
                let bits = base.trailing_zeros() as usize;
                let mut digit = 0;
                for bit in 0..bits {
                    let p = coordinate * bits + bit;
                    digit |= (((bytes[p / 8] >> (p % 8)) & 1) as u32) << bit;
                }
                digit
            } else {
                let digit = (&number % base).to_u32().expect("base <= 96");
                number /= base;
                digit
            };
            for r in 0..3 {
                let value = digit % bases[r];
                digit /= bases[r];
                let filled = full & (1 << r) != 0;
                if filled || value != 0 {
                    let index = (value - u32::from(!filled)) as usize;
                    entries.push(Entry {
                        coordinate: coordinate as u32,
                        code: palette[r][index],
                    });
                }
            }
        }
        if !base.is_power_of_two() && number != BigUint::from(0u8) {
            return Err("dense radix overflow".into());
        }
    } else {
        return Err("unknown compact BinAA mode".into());
    }
    let out = CompactMsg(ProtMsg {
        instance: InstanceId::new(epoch, None, slot),
        round,
        entries,
    });
    // Enforce exact palette, full-role flags, minimal varints/mode, sorted unique
    // slots and zero padding. This bounds alternative encodings of the same update.
    if out.encode()? != raw {
        return Err("noncanonical compact BinAA".into());
    }
    Ok(out)
}
impl Serialize for CompactMsg {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let bytes = self.encode().map_err(serde::ser::Error::custom)?;
        let mut tuple = serializer.serialize_tuple(bytes.len())?;
        for b in bytes {
            tuple.serialize_element(&b)?;
        }
        tuple.end()
    }
}
impl<'de> Deserialize<'de> for CompactMsg {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct MessageVisitor;
        impl<'de> Visitor<'de> for MessageVisitor {
            type Value = CompactMsg;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("canonical compact91 BinAA bytes")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                read(|| {
                    seq.next_element::<u8>()
                        .map_err(|e| e.to_string())?
                        .ok_or_else(|| "truncated compact BinAA".into())
                })
                .map_err(A::Error::custom)
            }
        }
        // This is a bounded binary tuple protocol, not a self-describing JSON format.
        deserializer.deserialize_tuple(MAX_ENCODED_BYTES, MessageVisitor)
    }
}
