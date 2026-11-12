//! Canonical compact91 encoding; compatible with the original sparse/radix format.
//! Only already-ready updates are encoded; no timers or cross-coordinate barrier.
use crate::{Entry, ProtMsg, MAX_ROUNDS};
use serde::{
    de::{Error as _, SeqAccess, Visitor},
    ser::SerializeTuple,
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::{borrow::Cow, fmt};
use types::InstanceId;
#[path = "compact_radix.rs"]
mod radix;

pub const MAX_PARTIES: usize = 91;
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
fn validate(entries: &[Entry], round: u32) -> Result<(), String> {
    if round == 0 || round > MAX_ROUNDS || entries.is_empty() || entries.len() > 3 * MAX_PARTIES {
        return Err("compact BinAA header/entry limit".into());
    }
    let mut previous = None;
    let mut previous_role = None;
    for e in entries {
        if e.coordinate as usize >= MAX_PARTIES
            || e.code > 10
            || (round == 1 && e.code < 5 && e.code != 2 && e.code != 3)
        {
            return Err("compact BinAA coordinate/code".into());
        }
        let key = (e.coordinate, e.code);
        let slot = (e.coordinate, role(e.code));
        if previous.is_some_and(|p| p >= key) || previous_role == Some(slot) {
            return Err("noncanonical or duplicate BinAA coordinate/role".into());
        }
        previous = Some(key);
        previous_role = Some(slot);
    }
    Ok(())
}
fn normalized(msg: &ProtMsg) -> Result<Cow<'_, [Entry]>, String> {
    if msg.instance.dealer.is_some() || msg.entries.len() > 3 * MAX_PARTIES {
        return Err("compact BinAA header/entry limit".into());
    }
    let entries = if msg
        .entries
        .windows(2)
        .all(|p| (p[0].coordinate, p[0].code) <= (p[1].coordinate, p[1].code))
    {
        Cow::Borrowed(msg.entries.as_slice())
    } else {
        let mut entries = msg.entries.clone();
        entries.sort_unstable_by_key(|e| (e.coordinate, e.code));
        Cow::Owned(entries)
    };
    validate(&entries, msg.round)?;
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
struct Palette {
    values: [[u8; 5]; 3],
    lengths: [u32; 3],
    positions: [u32; 11],
}
impl Palette {
    fn new(mask: u16) -> Self {
        let mut p = Self {
            values: [[0; 5]; 3],
            lengths: [0; 3],
            positions: [0; 11],
        };
        for code in 0..11 {
            if mask & (1 << code) != 0 {
                let r = role(code);
                p.values[r][p.lengths[r] as usize] = code;
                p.positions[code as usize] = p.lengths[r];
                p.lengths[r] += 1;
            }
        }
        p
    }
    fn radices(&self, full: u8) -> Result<[u32; 3], String> {
        let mut bases = [0; 3];
        for (r, base) in bases.iter_mut().enumerate() {
            let filled = full & (1 << r) != 0;
            if filled && self.lengths[r] == 0 {
                return Err("empty full role".into());
            }
            *base = self.lengths[r] + u32::from(!filled);
        }
        Ok(bases)
    }
}
struct DensePlan {
    n: usize,
    full: u8,
    metadata: u32,
    palette: Palette,
    bases: [u32; 3],
    base: u32,
    length: usize,
}
impl DensePlan {
    // Entries were already checked for ordering, coordinate bounds and role uniqueness.
    fn new(entries: &[Entry]) -> Self {
        let n = entries.last().unwrap().coordinate as usize + 1;
        let mut counts = [0; 3];
        let mut mask = 0;
        for e in entries {
            counts[role(e.code)] += 1;
            mask |= 1 << e.code;
        }
        let full = counts
            .iter()
            .enumerate()
            .fold(0, |v, (r, &k)| v | (u8::from(k == n) << r));
        let palette = Palette::new(mask);
        let bases = palette.radices(full).expect("observed nonempty palette");
        let base = bases.iter().product();
        let metadata = (n as u32 - 1) | ((mask as u32) << 7) | ((full as u32) << 18);
        Self {
            n,
            full,
            metadata,
            palette,
            bases,
            base,
            length: radix::byte_len(base, n),
        }
    }
    fn selection(&self, k: usize) -> (u16, usize) {
        if let Some((mode, length)) = sparse_shape(k) {
            if length <= 3 + self.length {
                return (mode, length);
            }
        }
        (DENSE, 3 + self.length)
    }
    fn append(&self, entries: &[Entry], out: &mut Vec<u8>) {
        out.extend_from_slice(&self.metadata.to_le_bytes()[..3]);
        if self.base == 1 {
            return;
        }
        let multipliers = [1, self.bases[0], self.bases[0] * self.bases[1]];
        let mut digits = [0u32; MAX_PARTIES];
        for e in entries {
            let r = role(e.code);
            let value =
                self.palette.positions[e.code as usize] + u32::from(self.full & (1 << r) == 0);
            digits[e.coordinate as usize] += multipliers[r] * value;
        }
        if self.base.is_power_of_two() {
            let bits = self.base.trailing_zeros() as usize;
            let start = out.len();
            out.resize(start + self.length, 0);
            for (i, &digit) in digits[..self.n].iter().enumerate() {
                put_bits(&mut out[start..], i * bits, bits, digit);
            }
        } else {
            let mut number = radix::Number::zero();
            for &digit in digits[..self.n].iter().rev() {
                number.mul_add(self.base, digit);
            }
            number.append(out, self.length);
        }
    }
}
fn sparse_shape(k: usize) -> Option<(u16, usize)> {
    (k <= 256).then_some((
        if k <= 12 { k as u16 - 1 } else { 12 },
        usize::from(k > 12) + (10 * k).div_ceil(8),
    ))
}
fn put_bits(out: &mut [u8], position: usize, width: usize, value: u32) {
    let offset = position % 8;
    let value = value << offset;
    for j in 0..(offset + width).div_ceil(8) {
        out[position / 8 + j] |= (value >> (8 * j)) as u8;
    }
}
fn get_bits(bytes: &[u8], position: usize, width: usize) -> u32 {
    let offset = position % 8;
    let mut value = 0;
    for j in 0..(offset + width).div_ceil(8) {
        value |= (bytes[position / 8 + j] as u32) << (8 * j);
    }
    (value >> offset) & ((1 << width) - 1)
}
fn padding_is_zero(bytes: &[u8], bits: usize) -> bool {
    bits.is_multiple_of(8) || bytes.last().is_some_and(|b| *b >> (bits % 8) == 0)
}
fn append_sparse(entries: &[Entry], out: &mut Vec<u8>) {
    let k = entries.len();
    if k > 12 {
        out.push((k - 1) as u8);
    }
    let start = out.len();
    out.resize(start + (10 * k).div_ceil(8), 0);
    for (i, e) in entries.iter().enumerate() {
        put_bits(
            &mut out[start..],
            10 * i,
            10,
            e.coordinate * 11 + e.code as u32,
        );
    }
}
impl CompactMsg {
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let _profile = util::profile::span("binaa.compact.encode");
        let entries = normalized(&self.0)?;
        // One or two sparse tokens are no longer than even a radix-one dense body.
        let plan = (entries.len() > 2).then(|| DensePlan::new(&entries));
        let (mode, length) = plan.as_ref().map_or_else(
            || sparse_shape(entries.len()).unwrap(),
            |p| p.selection(entries.len()),
        );
        let mut out = Vec::with_capacity(22 + length);
        varint(self.0.instance.epoch, &mut out);
        varint(self.0.instance.slot, &mut out);
        out.extend_from_slice(&((mode << 12) | (self.0.round as u16 - 1)).to_le_bytes());
        if mode == DENSE {
            plan.as_ref().unwrap().append(&entries, &mut out);
        } else {
            append_sparse(&entries, &mut out);
        }
        debug_assert!(out.len() <= MAX_ENCODED_BYTES);
        Ok(out)
    }
    pub fn decode(raw: &[u8]) -> Result<Self, String> {
        let mut position = 0;
        let out = read(|| {
            let b = raw
                .get(position)
                .copied()
                .ok_or("truncated compact BinAA")?;
            position += 1;
            Ok(b)
        })?;
        if position != raw.len() {
            return Err("trailing compact BinAA bytes".into());
        }
        Ok(out)
    }
}
fn read(mut input: impl FnMut() -> Result<u8, String>) -> Result<CompactMsg, String> {
    let _profile = util::profile::span("binaa.compact.decode");
    let mut consumed = 0;
    let mut byte = || {
        if consumed >= MAX_ENCODED_BYTES {
            return Err("compact BinAA byte limit".into());
        }
        let b = input()?;
        consumed += 1;
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
                if j > 0 && b == 0 {
                    return Err("nonminimal varint".into());
                }
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
    let mut entries;
    let mut dense_metadata = None;
    if mode < DENSE {
        let k = if mode < 12 {
            mode as usize + 1
        } else {
            byte()? as usize + 1
        };
        if k > 61 || (mode == 12 && k <= 12) {
            return Err("nonminimal sparse BinAA length".into());
        }
        let bytes: Vec<_> = (0..(10 * k).div_ceil(8))
            .map(|_| byte())
            .collect::<Result<_, _>>()?;
        if !padding_is_zero(&bytes, 10 * k) {
            return Err("nonzero sparse padding".into());
        }
        entries = Vec::with_capacity(k);
        for i in 0..k {
            let token = get_bits(&bytes, 10 * i, 10);
            if token >= 11 * MAX_PARTIES as u32 {
                return Err("invalid packed token".into());
            }
            entries.push(Entry {
                coordinate: token / 11,
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
        let palette = Palette::new(mask);
        let bases = palette.radices(full)?;
        let base: u32 = bases.iter().product();
        let length = radix::byte_len(base, n);
        let bytes: Vec<_> = (0..length).map(|_| byte()).collect::<Result<_, _>>()?;
        let bits = base.trailing_zeros() as usize;
        if base.is_power_of_two() && !padding_is_zero(&bytes, n * bits) {
            return Err("nonzero dense digit padding".into());
        }
        let mut number = radix::Number::from_bytes(&bytes);
        entries = Vec::with_capacity(3 * n);
        for coordinate in 0..n {
            let mut digit = if base.is_power_of_two() {
                get_bits(&bytes, coordinate * bits, bits)
            } else {
                number.div_rem(base)
            };
            for (r, &role_base) in bases.iter().enumerate() {
                let value = digit % role_base;
                digit /= role_base;
                let filled = full & (1 << r) != 0;
                if filled || value != 0 {
                    let index = (value - u32::from(!filled)) as usize;
                    entries.push(Entry {
                        coordinate: coordinate as u32,
                        code: palette.values[r][index],
                    });
                }
            }
        }
        if !base.is_power_of_two() && !number.is_zero() {
            return Err("dense radix overflow".into());
        }
        dense_metadata = Some(metadata);
    } else {
        return Err("unknown compact BinAA mode".into());
    }
    validate(&entries, round)?;
    // These checks replace re-encoding, not canonicality: shortest varints,
    // ordered unique slots, zero padding and radix range were checked above.
    // Exact observed metadata and the same sparse-tie choice fix all remaining bits.
    if entries.len() <= 2 {
        if mode != sparse_shape(entries.len()).unwrap().0 {
            return Err("nonminimal compact BinAA mode".into());
        }
    } else {
        let plan = DensePlan::new(&entries);
        if plan.selection(entries.len()).0 != mode
            || dense_metadata.is_some_and(|m| m != plan.metadata)
        {
            return Err("noncanonical compact BinAA mode or palette".into());
        }
    }
    Ok(CompactMsg(ProtMsg {
        instance: InstanceId::new(epoch, None, slot),
        round,
        entries,
    }))
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
        deserializer.deserialize_tuple(MAX_ENCODED_BYTES, MessageVisitor)
    }
}
