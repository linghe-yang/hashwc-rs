//! Compact header, systematic receipts, and bounded certificates under WAVID's root.
//! Only authorized recoverers need the bulk. Other verifiers regenerate success locally.
use crate::{
    Context, Opening, PrivateShare, Public, ax,
    terminal::{self, Terminal},
};
use anyhow::{Result, ensure};
use bincode::Options;
use crypto::{Block, hash, input_commitment, wire_commitment};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use wavid::{Codec, Prepared, SourceOpening, StorageFault};
use wcss::Setup;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub setup_id: Block,
    pub context_id: Block,
    pub root: Block,
    pub file_bytes: usize,
}
impl Header {
    pub const BYTES: usize = 112;
    pub fn new(setup: &Setup, context: &Context, root: Block) -> Self {
        Self {
            setup_id: setup.id(),
            context_id: context.id(),
            root,
            file_bytes: Public::encoded_len(setup),
        }
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut out = b"WHCCST01".to_vec();
        out.extend(self.setup_id);
        out.extend(self.context_id);
        out.extend(self.root);
        out.extend((self.file_bytes as u64).to_le_bytes());
        out
    }
    pub fn decode(setup: &Setup, context: &Context, raw: &[u8]) -> Result<Self> {
        ensure!(
            raw.len() == Self::BYTES && &raw[..8] == b"WHCCST01",
            "header format"
        );
        let h = Self::new(setup, context, raw[72..104].try_into()?);
        ensure!(raw == h.encode(), "header context/layout");
        Ok(h)
    }
    pub fn id(&self) -> Block {
        hash(b"whcc/striped/header/v1", &[&self.encode()])
    }
}
/// Existing AX bytes are the sole source file. Fields may cross 32-byte blocks.
#[derive(Clone, Debug)]
pub struct Layout {
    pub n: usize,
    pub nodes: usize,
    pub gates: usize,
    pub bytes: usize,
}
impl Layout {
    pub fn new(s: &Setup) -> Self {
        Self {
            n: s.circuit().policy().n(),
            nodes: s.circuit().nodes(),
            gates: s.circuit().gates().len(),
            bytes: Public::encoded_len(s),
        }
    }
    pub fn input(&self, i: usize) -> usize {
        104 + 32 * i
    }
    pub fn wire(&self, i: usize) -> usize {
        104 + 32 * (self.n + i)
    }
    pub fn gate(&self, i: usize, j: usize) -> usize {
        104 + 32 * (self.n + self.nodes) + 64 * i + 32 * j
    }
    pub fn key(&self) -> usize {
        104 + 32 * (self.n + self.nodes) + 64 * self.gates
    }
    pub fn cipher(&self) -> usize {
        self.key() + 64
    }
    pub fn prefix(s: &Setup, c: &Context) -> Vec<u8> {
        let mut b = b"HWAX0001".to_vec();
        b.extend(s.id());
        b.extend(c.id());
        b
    }
    pub fn receipt_ranges(&self, i: usize) -> Vec<(usize, usize)> {
        vec![(0, 72), (self.input(i), 32), (self.wire(i + 2), 32)]
    }
    pub fn ranges(&self, s: &Setup, t: &Terminal) -> Result<Vec<(usize, usize)>> {
        let mut r = vec![(0, 72)];
        match t {
            Terminal::TrueFault => r.extend([(72, 32), (self.wire(1), 32)]),
            Terminal::InputFault { party, .. } => {
                ensure!(*party < self.n, "party");
                r.extend([(self.input(*party), 32), (self.wire(party + 2), 32)]);
            }
            Terminal::GateFault {
                wire,
                branches,
                tokens,
            } => {
                ensure!(
                    *wire >= s.circuit().base() && *wire < self.nodes,
                    "gate index"
                );
                let g = s.circuit().gates()[wire - s.circuit().base()];
                ensure!(
                    match g.op {
                        wcss::Op::And => *branches == 3,
                        wcss::Op::Or => matches!(branches, 1 | 2),
                    },
                    "gate branches"
                );
                r.push((self.wire(*wire), 32));
                for (j, src) in [g.left, g.right].into_iter().enumerate() {
                    if branches & (1 << j) != 0 {
                        r.extend([
                            (self.wire(src), 32),
                            (self.gate(wire - s.circuit().base(), j), 32),
                        ]);
                    } else {
                        ensure!(tokens[j] == [0; 32], "unused branch");
                    }
                }
            }
            Terminal::RootFault { .. } => r.extend([
                (self.wire(s.circuit().output()), 32),
                (self.key(), 32),
                (self.cipher(), 64),
            ]),
            Terminal::Success(_) => anyhow::bail!("success has no field proof"),
        }
        Ok(r)
    }
}
fn blocks(ranges: &[(usize, usize)]) -> BTreeSet<usize> {
    ranges
        .iter()
        .flat_map(|&(offset, len)| offset / 32..(offset + len).div_ceil(32))
        .collect()
}
pub fn openings(
    codec: &Codec,
    prepared: &Prepared,
    ranges: &[(usize, usize)],
) -> Result<Vec<SourceOpening>> {
    blocks(ranges)
        .into_iter()
        .map(|b| codec.source_opening(prepared, b))
        .collect()
}
fn authenticate(
    codec: &Codec,
    h: &Header,
    proofs: &[SourceOpening],
    ranges: &[(usize, usize)],
) -> bool {
    let expected = blocks(ranges);
    proofs.len() == expected.len()
        && proofs.iter().zip(expected).all(|(p, b)| {
            p.stripe == b / codec.k
                && p.fragment.index == b % codec.k
                && codec.verify_source(h.root, p)
        })
}
fn field(codec: &Codec, proofs: &[SourceOpening], offset: usize, len: usize) -> Vec<u8> {
    (offset..offset + len)
        .map(|pos| {
            let block = pos / 32;
            proofs
                .iter()
                .find(|p| p.stripe == block / codec.k && p.fragment.index == block % codec.k)
                .expect("authenticated field")
                .fragment
                .data[pos % 32]
        })
        .collect()
}
fn decode<T: serde::de::DeserializeOwned>(raw: &[u8], max: usize) -> Result<T> {
    ensure!(raw.len() <= max, "evidence size");
    Ok(bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(max as u64)
        .reject_trailing_bytes()
        .deserialize(raw)?)
}
/// Bounds include complete Merkle paths, but never a dealer-sized vector of fields.
pub fn max_evidence_bytes(codec: &Codec) -> usize {
    256 * (codec.k + 32)
        * (codec.m.next_power_of_two().trailing_zeros() as usize
            + codec.q.next_power_of_two().trailing_zeros() as usize
            + 8)
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub share: Vec<u8>,
    pub fields: Vec<SourceOpening>,
}
impl Receipt {
    pub fn new(s: &Setup, codec: &Codec, p: &Prepared, share: &PrivateShare) -> Result<Self> {
        Ok(Self {
            share: share.encode().to_vec(),
            fields: openings(codec, p, &Layout::new(s).receipt_ranges(share.party))?,
        })
    }
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("receipt serialization")
    }
    pub fn decode(codec: &Codec, raw: &[u8]) -> Result<Self> {
        decode(raw, max_evidence_bytes(codec))
    }
    pub fn verify(
        &self,
        s: &Setup,
        c: &Context,
        codec: &Codec,
        h: &Header,
        party: usize,
    ) -> Option<PrivateShare> {
        let share = PrivateShare::decode(&self.share).ok()?;
        if party >= s.circuit().policy().n()
            || share.party != party
            || share.setup_id != s.id()
            || share.context_id != c.id()
        {
            return None;
        }
        let l = Layout::new(s);
        if !authenticate(codec, h, &self.fields, &l.receipt_ranges(party))
            || field(codec, &self.fields, 0, 72) != Layout::prefix(s, c)
        {
            return None;
        }
        if field(codec, &self.fields, l.input(party), 32)
            != input_commitment(&c.id(), party, &share.token)
            || field(codec, &self.fields, l.wire(party + 2), 32)
                != wire_commitment(&c.id(), party + 2, &share.token)
        {
            return None;
        }
        Some(share)
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub enum Evidence {
    Success(Opening),
    Storage(StorageFault),
    Format(Vec<SourceOpening>),
    Semantic {
        fault: Terminal,
        fields: Vec<SourceOpening>,
    },
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub header_id: Block,
    pub evidence: Evidence,
}
impl Certificate {
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("certificate serialization")
    }
    pub fn decode(codec: &Codec, raw: &[u8]) -> Result<Self> {
        decode(raw, max_evidence_bytes(codec))
    }
}
pub fn in_range(message: &Block, bits: usize) -> bool {
    bits <= 256 && (0..256 - bits).all(|i| message[i / 8] & (1 << (7 - i % 8)) == 0)
}
pub fn verify_opening(
    s: &Setup,
    c: &Context,
    codec: &Codec,
    h: &Header,
    o: &Opening,
    bits: usize,
) -> bool {
    if !in_range(&o.message, bits) {
        return false;
    }
    ax::generate(s, c, o)
        .ok()
        .and_then(|(p, _)| codec.prepare(&p.encode()).ok())
        .is_some_and(|p| p.root == h.root)
}
/// Rebuild only the fields needed by the local semantic predicate. RootFault
/// is handled separately: a sparse transcript must NEVER be used for regeneration.
fn sparse(
    s: &Setup,
    c: &Context,
    codec: &Codec,
    proofs: &[SourceOpening],
    ranges: &[(usize, usize)],
) -> Public {
    let mut raw = vec![0; Public::encoded_len(s)];
    raw[..72].copy_from_slice(&Layout::prefix(s, c));
    for &(o, len) in ranges {
        raw[o..o + len].copy_from_slice(&field(codec, proofs, o, len));
    }
    Public::decode(s, c, &raw).expect("authenticated format")
}
pub fn verify(
    s: &Setup,
    c: &Context,
    codec: &Codec,
    h: &Header,
    cert: &Certificate,
    bits: usize,
) -> bool {
    if h.setup_id != s.id()
        || h.context_id != c.id()
        || h.file_bytes != Public::encoded_len(s)
        || cert.header_id != h.id()
    {
        return false;
    }
    match &cert.evidence {
        Evidence::Success(o) => verify_opening(s, c, codec, h, o, bits),
        Evidence::Storage(f) => codec.verify_fault(h.root, f),
        Evidence::Format(p) => {
            authenticate(codec, h, p, &[(0, 72)]) && field(codec, p, 0, 72) != Layout::prefix(s, c)
        }
        Evidence::Semantic { fault, fields } => {
            let Ok(ranges) = Layout::new(s).ranges(s, fault) else {
                return false;
            };
            if !authenticate(codec, h, fields, &ranges)
                || field(codec, fields, 0, 72) != Layout::prefix(s, c)
            {
                return false;
            }
            let p = sparse(s, c, codec, fields, &ranges);
            if let Terminal::RootFault { token } = fault {
                wire_commitment(&c.id(), s.circuit().output(), token)
                    == p.base.wires[s.circuit().output()]
                    && !verify_opening(
                        s,
                        c,
                        codec,
                        h,
                        &terminal::candidate(c, &p, s.circuit().output(), token),
                        bits,
                    )
            } else {
                terminal::verify(s, c, &p, fault)
            }
        }
    }
}
pub fn certify(
    s: &Setup,
    codec: &Codec,
    h: &Header,
    prepared: &Prepared,
    t: Terminal,
) -> Result<Certificate> {
    let evidence = match t {
        Terminal::Success(o) => Evidence::Success(o),
        fault => {
            let fields = openings(codec, prepared, &Layout::new(s).ranges(s, &fault)?)?;
            Evidence::Semantic { fault, fields }
        }
    };
    Ok(Certificate {
        header_id: h.id(),
        evidence,
    })
}
