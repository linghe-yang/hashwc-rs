//! Only coalesce packets already authorized by a protocol state transition.
//! No timers, quorum waits, or dependence on future input.
use super::Packet;
use anyhow::{Result, ensure};
use bincode::Options;
use std::collections::BTreeMap;

const TAG: u8 = 255;
const LIMIT: usize = 32 * 1024;
const COUNT: usize = 64;
fn container(p: &Packet) -> bool {
    p.epoch == 0 && p.dealer == usize::MAX && p.kind == TAG
}

fn wrap(packets: Vec<Packet>) -> Packet {
    if packets.len() == 1 {
        return packets.into_iter().next().unwrap();
    }
    let mut payload = Vec::new();
    for p in packets {
        let raw = bincode::serialize(&p).expect("Packet serialization");
        payload.extend_from_slice(&(raw.len() as u32).to_le_bytes());
        payload.extend_from_slice(&raw);
    }
    Packet {
        epoch: 0,
        dealer: usize::MAX,
        kind: TAG,
        payload,
    }
}

pub(crate) fn pack(ready: Vec<(usize, Packet)>) -> Result<Vec<(usize, Packet)>> {
    let mut groups: BTreeMap<usize, (Vec<Packet>, usize)> = BTreeMap::new();
    let mut out = Vec::new();
    for (recipient, packet) in ready {
        ensure!(!container(&packet), "nested ready-packet container");
        let size = bincode::serialized_size(&packet)? as usize + 4;
        let (pending, bytes) = groups.entry(recipient).or_default();
        if !pending.is_empty() && (*bytes + size > LIMIT || pending.len() == COUNT) {
            out.push((recipient, wrap(std::mem::take(pending))));
            *bytes = 0;
        }
        // A valid large individual packet uses the existing frame-limit checks.
        if size > LIMIT {
            out.push((recipient, packet));
        } else {
            *bytes += size;
            pending.push(packet);
        }
    }
    for (recipient, (pending, _)) in groups {
        if !pending.is_empty() {
            out.push((recipient, wrap(pending)));
        }
    }
    Ok(out)
}

pub(crate) fn unpack(packet: Packet) -> Vec<Packet> {
    if !container(&packet) {
        return vec![packet];
    }
    if packet.payload.len() > LIMIT {
        return Vec::new();
    }
    let mut raw = packet.payload.as_slice();
    let mut out = Vec::new();
    let mut count = 0;
    while !raw.is_empty() {
        count += 1;
        if count > COUNT || raw.len() < 4 {
            return Vec::new();
        }
        let length = u32::from_le_bytes(raw[..4].try_into().unwrap()) as usize;
        raw = &raw[4..];
        if length > raw.len() {
            return Vec::new();
        }
        // A malformed framed entry does not suppress unrelated valid entries.
        if let Ok(p) = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(LIMIT as u64)
            .reject_trailing_bytes()
            .deserialize::<Packet>(&raw[..length])
        {
            if !container(&p) {
                out.push(p);
            }
        }
        raw = &raw[length..];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    fn p(d: usize, len: usize) -> Packet {
        Packet {
            epoch: 9,
            dealer: d,
            kind: 2,
            payload: vec![d as u8; len],
        }
    }
    #[test]
    fn singleton_is_immediate_and_unchanged() {
        let v = pack(vec![(1, p(2, 17))]).unwrap();
        assert_eq!(v.len(), 1);
        assert!(!container(&v[0].1));
        assert_eq!(v[0].1.dealer, 2);
    }
    #[test]
    fn bounded_frames_preserve_per_recipient_order_and_large_packets() {
        let input = (0..150)
            .flat_map(|d| [(1, p(d, if d == 90 { 40000 } else { 500 })), (2, p(d, 4))])
            .collect();
        let frames = pack(input).unwrap();
        assert!(frames.len() < 30);
        let mut result: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for (to, frame) in frames {
            for item in unpack(frame) {
                result.entry(to).or_default().push(item.dealer);
            }
        }
        for ids in result.values() {
            assert_eq!(ids, &(0..150).collect::<Vec<_>>());
        }
    }
    #[test]
    fn malformed_entry_does_not_hide_valid_neighbors_and_nested_frames_are_rejected() {
        let mut frame = wrap(vec![p(1, 4), p(2, 4)]);
        let length = u32::from_le_bytes(frame.payload[..4].try_into().unwrap()) as usize;
        // Replace the first Packet with a four-byte invalid body, keeping framing valid.
        let mut raw = 4u32.to_le_bytes().to_vec();
        raw.extend_from_slice(&[0; 4]);
        raw.extend_from_slice(&frame.payload[4 + length..]);
        frame.payload = raw;
        let out = unpack(frame);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].dealer, 2);
        assert!(pack(vec![(1, wrap(vec![p(1, 1), p(2, 1)]))]).is_err());
    }
    #[test]
    fn encrypted_batch_binds_channel_and_saves_bytes() {
        let a = super::super::Cipher::new(&super::super::tests::node(0), "recovery").unwrap();
        let b = super::super::Cipher::new(&super::super::tests::node(1), "recovery").unwrap();
        let packets = vec![p(1, 306), p(2, 306), p(3, 306)];
        let separate: usize = packets
            .iter()
            .map(|p| bincode::serialized_size(&a.seal(1, p).unwrap()).unwrap() as usize + 132)
            .sum();
        let frame = wrap(packets);
        let sealed = a.seal(1, &frame).unwrap();
        assert!(bincode::serialized_size(&sealed).unwrap() as usize + 132 < separate);
        assert_eq!(unpack(b.open(0, &sealed).unwrap()).len(), 3);
        assert!(
            super::super::Cipher::new(&super::super::tests::node(1), "private")
                .unwrap()
                .open(0, &sealed)
                .is_err()
        );
    }
}
