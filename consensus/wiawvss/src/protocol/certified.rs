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
use wavid::{Codec, Prepared, SourceOpening, StorageFault, ValidatedFile};
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
    pub fn prefix(s: &Setup, c: &Context) -> [u8; 72] {
        let mut b = [0; 72];
        b[..8].copy_from_slice(b"HWAX0001");
        b[8..40].copy_from_slice(&s.id());
        b[40..72].copy_from_slice(&c.id());
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
fn blocks(block_bytes: usize, ranges: &[(usize, usize)]) -> BTreeSet<usize> {
    ranges
        .iter()
        .flat_map(|&(offset, len)| offset / block_bytes..(offset + len).div_ceil(block_bytes))
        .collect()
}
/// Common proof interface for production lazy files and diagnostic eager encodings.
pub trait ProofSource {
    fn open(&self, codec: &Codec, block: usize) -> Result<SourceOpening>;
}
impl ProofSource for Prepared {
    fn open(&self, codec: &Codec, block: usize) -> Result<SourceOpening> {
        codec.source_opening(self, block)
    }
}
impl ProofSource for ValidatedFile {
    fn open(&self, codec: &Codec, block: usize) -> Result<SourceOpening> {
        ensure!(
            self.coding_context() == codec.context && self.parameters() == codec.parameters(),
            "proof provider context"
        );
        self.open_source(block)
    }
}
pub fn openings(
    codec: &Codec,
    prepared: &impl ProofSource,
    ranges: &[(usize, usize)],
) -> Result<Vec<SourceOpening>> {
    blocks(codec.parameters().block_bytes, ranges)
        .into_iter()
        .map(|b| prepared.open(codec, b))
        .collect()
}
fn authenticate(
    codec: &Codec,
    h: &Header,
    proofs: &[SourceOpening],
    ranges: &[(usize, usize)],
) -> bool {
    let expected = blocks(codec.parameters().block_bytes, ranges);
    proofs.len() == expected.len()
        && proofs.iter().zip(expected).all(|(p, b)| {
            p.stripe == b / codec.k
                && p.fragment.index == b % codec.k
                && codec.verify_source(h.root, p)
        })
}
fn field<const N: usize>(codec: &Codec, proofs: &[SourceOpening], offset: usize) -> [u8; N] {
    let mut out = [0; N];
    let block_bytes = codec.parameters().block_bytes;
    let mut copied = 0;
    while copied < N {
        let pos = offset + copied;
        let block = pos / block_bytes;
        let proof = proofs
            .iter()
            .find(|p| p.stripe == block / codec.k && p.fragment.index == block % codec.k)
            .expect("authenticated field");
        let start = pos % block_bytes;
        let take = (block_bytes - start).min(N - copied);
        out[copied..copied + take].copy_from_slice(&proof.fragment.data[start..start + take]);
        copied += take;
    }
    out
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
    (256 + codec.parameters().block_bytes)
        * (codec.k + 32)
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
    pub fn new(
        s: &Setup,
        codec: &Codec,
        p: &impl ProofSource,
        share: &PrivateShare,
    ) -> Result<Self> {
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
            || field::<72>(codec, &self.fields, 0) != Layout::prefix(s, c)
        {
            return None;
        }
        if field::<32>(codec, &self.fields, l.input(party))
            != input_commitment(&c.id(), party, &share.token)
            || field::<32>(codec, &self.fields, l.wire(party + 2))
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
        .and_then(|(p, _)| codec.commit_file(p.encode()).ok())
        .is_some_and(|p| p.root() == h.root)
}
/// The caller authenticates Layout::ranges before any field access.
pub struct AuthenticatedFields<'a> {
    pub layout: Layout,
    pub codec: &'a Codec,
    pub proofs: &'a [SourceOpening],
}
impl terminal::SemanticFields for AuthenticatedFields<'_> {
    fn true_token(&self) -> Block {
        field(self.codec, self.proofs, 72)
    }
    fn input(&self, party: usize) -> Block {
        field(self.codec, self.proofs, self.layout.input(party))
    }
    fn wire(&self, wire: usize) -> Block {
        field(self.codec, self.proofs, self.layout.wire(wire))
    }
    fn gate(&self, gate: usize, branch: usize) -> Block {
        field(self.codec, self.proofs, self.layout.gate(gate, branch))
    }
}
pub fn verify(
    s: &Setup,
    c: &Context,
    codec: &Codec,
    h: &Header,
    cert: &Certificate,
    bits: usize,
) -> bool {
    if c.validate(s).is_err()
        || h.setup_id != s.id()
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
            authenticate(codec, h, p, &[(0, 72)])
                && field::<72>(codec, p, 0) != Layout::prefix(s, c)
        }
        Evidence::Semantic { fault, fields } => {
            let Ok(ranges) = Layout::new(s).ranges(s, fault) else {
                return false;
            };
            if !authenticate(codec, h, fields, &ranges)
                || field::<72>(codec, fields, 0) != Layout::prefix(s, c)
            {
                return false;
            }
            let p = AuthenticatedFields {
                layout: Layout::new(s),
                codec,
                proofs: fields,
            };
            if let Terminal::RootFault { token } = fault {
                wire_commitment(&c.id(), s.circuit().output(), token)
                    == field::<32>(codec, fields, p.layout.wire(s.circuit().output()))
                    && !verify_opening(
                        s,
                        c,
                        codec,
                        h,
                        &terminal::candidate_fields(
                            c,
                            s.circuit().output(),
                            token,
                            &field(codec, fields, p.layout.key()),
                            &field(codec, fields, p.layout.cipher()),
                            &field(codec, fields, p.layout.cipher() + 32),
                        ),
                        bits,
                    )
            } else {
                terminal::verify_local_fault(s, c, &p, fault)
            }
        }
    }
}
pub fn certify(
    s: &Setup,
    codec: &Codec,
    h: &Header,
    prepared: &impl ProofSource,
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

/// A local recovery binds the exact decoded public bytes to the already validated
/// WAVID file before reusing its full AX check. Remote certificates still use verify().
pub struct RecoverySource<'a> {
    pub setup: &'a Setup,
    pub context: &'a Context,
    pub codec: &'a Codec,
    pub header: &'a Header,
    pub public: &'a Public,
    pub file: &'a ValidatedFile,
}
impl RecoverySource<'_> {
    pub fn recover<'a>(
        &self,
        shares: impl IntoIterator<Item = &'a PrivateShare>,
        bits: usize,
    ) -> Result<Option<Certificate>> {
        let Self {
            setup,
            context,
            codec,
            header,
            public,
            file,
        } = *self;
        ensure!(bits <= 256, "contribution bits");
        ensure!(
            header.setup_id == setup.id()
                && header.context_id == context.id()
                && header.file_bytes == Public::encoded_len(setup)
                && file.len() == header.file_bytes
                && file.root() == header.root
                && file.coding_context() == codec.context
                && file.parameters() == codec.parameters(),
            "local recovery source binding"
        );
        let terminal = match terminal::recover_bounded_iter(setup, context, public, shares, bits) {
            Ok(t) => t,
            Err(types::Error::InsufficientShares) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        ensure!(public.matches_encoded(file), "local recovery public bytes");
        // Success was fully regenerated against the exact root-bound file.
        // Local faults were checked against that same file; certify authenticates
        // their fields. RootFault includes the output token and retains the full
        // regeneration check above (or the public message-range failure).
        Ok(Some(certify(setup, codec, header, file, terminal)?))
    }
}

/// Safe transport budget for all file lengths accepted by WAVID, including a
/// coding witness with k=n blocks and local semantic proofs (at most 13 openings).
/// Includes a conservative 61-byte Packet/sealed envelope; not an optimizer.
pub fn evidence_transport_bound(n: usize, block_bytes: usize) -> usize {
    let proof_bytes = |leaves: usize| {
        let depth = leaves.next_power_of_two().max(2).trailing_zeros() as usize;
        16 + 32 * (depth + 2) + depth
    };
    let q = wavid::MAX_FILE_BYTES.div_ceil(n * block_bytes);
    let pm = proof_bytes(4 * n);
    let pq = proof_bytes(q);
    let source = 56 + block_bytes + pm + pq;
    let coding = 88 + pq + n * (16 + block_bytes + pm);
    let semantic = 121 + 13 * source;
    coding.max(semantic) + 61
}
