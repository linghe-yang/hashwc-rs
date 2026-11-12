//! Hash commitment sharing and reconstruction over the weighted circuit.
use super::circuit::{Circuit, Limits, Op};
use crypto::{Block, edge_pad, equal, hash, input_commitment, wire_commitment, xor};
use std::sync::Arc;
use types::{Error, Policy, Result};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend {
    Independent,
    GeneratedAnd0Or1,
}
impl Backend {
    pub fn name(self) -> &'static str {
        match self {
            Self::Independent => "independent-two-ciphertexts",
            Self::GeneratedAnd0Or1 => "generated-and0-or1",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Setup {
    pub circuit: Circuit,
    pub id: Block,
    backend: Backend,
    or_indices: Vec<Option<usize>>,
    correction_blocks: usize,
    boundary: Option<Arc<super::boundary::Plan>>,
}
impl Setup {
    pub fn new(policy: Policy, limits: Limits) -> Result<Self> {
        let circuit = Circuit::build(policy, limits)?;
        let id = hash(b"setup/odd-even/p25519/token256", &[&circuit.encode()]);
        Ok(Self::with_backend(circuit, id, Backend::Independent))
    }
    /// Opt-in exact circuit optimization; new remains the legacy baseline.
    /// A separate domain prevents accidentally mixing compiler modes.
    pub fn new_optimized(policy: Policy, limits: Limits) -> Result<Self> {
        let circuit = Circuit::build_optimized(policy, limits)?;
        let id = hash(
            b"setup/exact-candidates-v1/p25519/token256",
            &[&circuit.encode()],
        );
        Ok(Self::with_backend(circuit, id, Backend::Independent))
    }
    /// Fixed compiler plus generated AND0/OR1 labels, with a distinct format domain.
    pub fn new_clean(policy: Policy, limits: Limits) -> Result<Self> {
        let circuit = Circuit::build_clean(policy, limits)?;
        let boundary = Arc::new(super::boundary::Plan::new(&circuit)?);
        let id = hash(
            b"setup/clean-v1/gcd-ordered-merge/and0-or1/columns4/retained-tag-v1/p25519/token256",
            &[&circuit.encode(), &boundary.id()],
        );
        let mut setup = Self::with_backend(circuit, id, Backend::GeneratedAnd0Or1);
        setup.boundary = Some(boundary);
        Ok(setup)
    }
    fn with_backend(circuit: Circuit, id: Block, backend: Backend) -> Self {
        let mut correction_blocks = 0;
        let or_indices = if backend == Backend::GeneratedAnd0Or1 {
            circuit
                .gates()
                .iter()
                .map(|g| {
                    if g.op == Op::Or {
                        let index = correction_blocks;
                        correction_blocks += 1;
                        Some(index)
                    } else {
                        None
                    }
                })
                .collect()
        } else {
            correction_blocks = 2 * circuit.gates().len();
            vec![]
        };
        Self {
            circuit,
            id,
            backend,
            or_indices,
            correction_blocks,
            boundary: None,
        }
    }
    pub fn backend(&self) -> Backend {
        self.backend
    }
    pub fn boundary(&self) -> Option<&Arc<super::boundary::Plan>> {
        self.boundary.as_ref()
    }
    pub fn pvr_wire_count(&self) -> usize {
        self.boundary()
            .map_or(self.circuit.nodes(), |p| p.wires().len())
    }
    pub fn correction_blocks(&self) -> usize {
        self.correction_blocks
    }
    /// Index in the serialized correction stream; absent branches have no bytes.
    pub fn correction_index(&self, gate: usize, branch: usize) -> Option<usize> {
        if gate >= self.circuit.gates().len() || branch > 1 {
            return None;
        }
        match self.backend {
            Backend::Independent => Some(2 * gate + branch),
            Backend::GeneratedAnd0Or1 => {
                if branch == 1 {
                    self.or_indices[gate]
                } else {
                    None
                }
            }
        }
    }
    pub fn circuit(&self) -> &Circuit {
        &self.circuit
    }
    pub fn id(&self) -> Block {
        self.id
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Public {
    pub true_token: Block,
    pub inputs: Vec<Block>,
    pub wires: Vec<Block>,
    pub gates: Vec<[Block; 2]>,
    /// Generated backend only: one block per OR, in original gate order.
    /// Keeping legacy pairs separate preserves its exact historical encoding.
    pub corrections: Vec<Block>,
    pub encrypted_key: Block,
    pub tag: Block,
}
impl Public {
    pub fn encoded_len(setup: &Setup) -> usize {
        96 + 32 * (setup.circuit.policy().n() + setup.circuit.nodes())
            + 32 * setup.correction_blocks()
    }
    pub fn valid_shape(&self, setup: &Setup) -> bool {
        valid_shape(setup, self, true)
    }
    pub fn valid_shape_with_wire_count(&self, setup: &Setup, wire_count: usize) -> bool {
        valid_shape_count(setup, self, wire_count)
    }
    pub fn byte_len(&self) -> usize {
        96 + 32 * (self.inputs.len() + self.wires.len() + self.corrections.len())
            + 64 * self.gates.len()
    }
    pub fn encoded_parts<'a>(&'a self, tag: &'a Block) -> impl Iterator<Item = &'a [u8]> {
        std::iter::once(&self.true_token)
            .chain(&self.inputs)
            .chain(&self.wires)
            .chain(self.gates.iter().flat_map(|pair| pair.iter()))
            .chain(&self.corrections)
            .chain([&self.encrypted_key, tag])
            .map(|block| block.as_slice())
    }
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        out.reserve(self.byte_len());
        for part in self.encoded_parts(&self.tag) {
            out.extend_from_slice(part);
        }
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.byte_len());
        self.encode_into(&mut out);
        out
    }
    pub fn decode(setup: &Setup, bytes: &[u8]) -> Result<Self> {
        Self::decode_with_wire_count(setup, bytes, setup.circuit.nodes())
    }
    /// Fixed-layout parsing only. A projected AX caller authenticates its own
    /// manifest and full Canon; ordinary CSS reconstruction still needs all digests.
    pub fn decode_with_wire_count(setup: &Setup, bytes: &[u8], wire_count: usize) -> Result<Self> {
        if bytes.len()
            != 96 + 32 * (setup.circuit.policy().n() + wire_count + setup.correction_blocks())
        {
            return Err(Error::Encoding);
        }
        let mut chunks = bytes.as_chunks::<32>().0.iter();
        let mut take = || -> Block { *chunks.next().expect("fixed layout validated") };
        Ok(Self {
            true_token: take(),
            inputs: (0..setup.circuit.policy().n()).map(|_| take()).collect(),
            wires: (0..wire_count).map(|_| take()).collect(),
            gates: (0..if setup.backend() == Backend::Independent {
                setup.circuit.gates().len()
            } else {
                0
            })
                .map(|_| [take(), take()])
                .collect(),
            corrections: (0..if setup.backend() == Backend::GeneratedAnd0Or1 {
                setup.correction_blocks()
            } else {
                0
            })
                .map(|_| take())
                .collect(),
            encrypted_key: take(),
            tag: take(),
        })
    }
    pub fn correction(&self, index: usize) -> Block {
        if self.gates.is_empty() {
            self.corrections[index]
        } else {
            self.gates[index / 2][index % 2]
        }
    }
}

fn generated_and(context: &Block, wire: usize, left: &Block, right: &Block) -> Block {
    hash(
        b"css/generated-and/v1",
        &[context, &(wire as u64).to_le_bytes(), left, right],
    )
}
fn generated_or(context: &Block, wire: usize, branch: usize, token: &Block) -> Block {
    hash(
        b"css/generated-or/v1",
        &[
            context,
            &(wire as u64).to_le_bytes(),
            &[branch as u8],
            token,
        ],
    )
}

/// Evaluate one legal gate witness. Callers authenticate its input labels first.
/// This is shared by ordinary CSS, local PVR recovery and remote fault verification.
pub fn evaluate_gate(
    setup: &Setup,
    context: &Block,
    index: usize,
    branches: u8,
    tokens: &[Block; 2],
    correction: impl FnMut(usize) -> Block,
) -> Option<Block> {
    evaluate_gate_with(
        setup,
        context,
        index,
        branches,
        tokens,
        correction,
        |op, wire, branch, tokens| match op {
            Op::And => generated_and(context, wire, &tokens[0], &tokens[1]),
            Op::Or => generated_or(context, wire, branch, &tokens[branch]),
        },
    )
}

/// Per-context gate evaluator for a sequence of gates. Protocol semantics and
/// transcript bytes are identical to evaluate_gate; only framing is reused.
pub struct GateEvaluator<'a> {
    setup: &'a Setup,
    context: Block,
    and_hash: crypto::HashTemplate<256, 3>,
    or_hash: crypto::HashTemplate<256, 3>,
}
impl<'a> GateEvaluator<'a> {
    pub fn new(setup: &'a Setup, context: &Block) -> Self {
        Self {
            setup,
            context: *context,
            and_hash: crypto::HashTemplate::new(b"css/generated-and/v1", &[context], [8, 32, 32])
                .expect("fixed gate frame"),
            or_hash: crypto::HashTemplate::new(b"css/generated-or/v1", &[context], [8, 1, 32])
                .expect("fixed gate frame"),
        }
    }
    pub fn evaluate(
        &mut self,
        index: usize,
        branches: u8,
        tokens: &[Block; 2],
        correction: impl FnMut(usize) -> Block,
    ) -> Option<Block> {
        evaluate_gate_with(
            self.setup,
            &self.context,
            index,
            branches,
            tokens,
            correction,
            |op, wire, branch, tokens| match op {
                Op::And => {
                    self.and_hash
                        .hash([&(wire as u64).to_le_bytes(), &tokens[0], &tokens[1]])
                }
                Op::Or => self.or_hash.hash([
                    &(wire as u64).to_le_bytes(),
                    &[branch as u8],
                    &tokens[branch],
                ]),
            },
        )
    }
}
fn evaluate_gate_with(
    setup: &Setup,
    context: &Block,
    index: usize,
    branches: u8,
    tokens: &[Block; 2],
    mut correction: impl FnMut(usize) -> Block,
    mut generated: impl FnMut(Op, usize, usize, &[Block; 2]) -> Block,
) -> Option<Block> {
    let g = setup.circuit().gates().get(index)?;
    if !(match g.op {
        Op::And => branches == 3,
        Op::Or => matches!(branches, 1 | 2),
    }) || (0..2).any(|j| branches & (1 << j) == 0 && tokens[j] != [0; 32])
    {
        return None;
    }
    let wire = setup.circuit().base() + index;
    if setup.backend() == Backend::GeneratedAnd0Or1 {
        return Some(match g.op {
            Op::And => generated(Op::And, wire, 0, tokens),
            Op::Or => {
                let branch = usize::from(branches == 2);
                let pad = generated(Op::Or, wire, branch, tokens);
                if branch == 0 {
                    pad
                } else {
                    xor(&pad, &correction(setup.correction_index(index, branch)?))
                }
            }
        });
    }
    let mut out = [0; 32];
    for (branch, src) in [g.left, g.right].into_iter().enumerate() {
        if branches & (1 << branch) != 0 {
            out = xor(
                &out,
                &xor(
                    &correction(setup.correction_index(index, branch)?),
                    &edge_pad(context, wire, branch, src, &tokens[branch]),
                ),
            );
        }
    }
    Some(out)
}
fn transcript_tag(context: &Block, root: &Block, public: &Public) -> Block {
    crypto::hash_with_tail(
        b"transcript",
        &[context, root],
        public.byte_len(),
        public.encoded_parts(&[0; 32]),
    )
}
/// Deterministic sharing is internal to AX. The seed must stay private.
pub fn share(
    setup: &Setup,
    context: &Block,
    key: &Block,
    seed: &Block,
) -> (Public, Zeroizing<Vec<Block>>) {
    share_with_wires(setup, context, key, seed, true)
}
pub(super) fn share_with_wires(
    setup: &Setup,
    context: &Block,
    key: &Block,
    seed: &Block,
    with_wires: bool,
) -> (Public, Zeroizing<Vec<Block>>) {
    share_internal(setup, context, key, seed, with_wires, true)
}
/// Generate exactly the same public fields without materializing private shares.
pub fn share_public(setup: &Setup, context: &Block, key: &Block, seed: &Block) -> Public {
    share_internal(setup, context, key, seed, true, false).0
}
/// PVR generation authenticates exactly the retained CSS record. Ordinary
/// full-wire and compact CSS keep their own reconstruction/tag formats.
pub fn share_pvr(
    setup: &Setup,
    context: &Block,
    key: &Block,
    seed: &Block,
) -> (Public, Zeroizing<Vec<Block>>) {
    share_selected(setup, context, key, seed, pvr_digests(setup), true)
}
/// Full canonical public regeneration, without unused private-share outputs.
pub fn share_pvr_public(setup: &Setup, context: &Block, key: &Block, seed: &Block) -> Public {
    share_selected(setup, context, key, seed, pvr_digests(setup), false).0
}
#[derive(Clone, Copy)]
enum WireDigests<'a> {
    None,
    All,
    Boundary(&'a super::boundary::Plan),
}
fn pvr_digests(setup: &Setup) -> WireDigests<'_> {
    setup
        .boundary()
        .map_or(WireDigests::All, |plan| WireDigests::Boundary(plan))
}
pub(super) fn share_internal(
    setup: &Setup,
    context: &Block,
    key: &Block,
    seed: &Block,
    with_wires: bool,
    with_shares: bool,
) -> (Public, Zeroizing<Vec<Block>>) {
    let digests = if with_wires {
        WireDigests::All
    } else {
        WireDigests::None
    };
    share_selected(setup, context, key, seed, digests, with_shares)
}
fn share_selected(
    setup: &Setup,
    context: &Block,
    key: &Block,
    seed: &Block,
    digests: WireDigests<'_>,
    with_shares: bool,
) -> (Public, Zeroizing<Vec<Block>>) {
    let c = &setup.circuit;
    let generated = setup.backend() == Backend::GeneratedAnd0Or1;
    // Final size is public and known. Allocate before writing secret tokens so
    // growth does not copy the entire accumulated token vector repeatedly.
    let mut tokens = Zeroizing::new(Vec::with_capacity(c.nodes()));
    tokens.extend(
        (0..if generated { c.base() } else { c.nodes() })
            .map(|v| hash(b"coins/token", &[seed, context, &(v as u64).to_le_bytes()])),
    );
    let mut p = Public {
        true_token: tokens[1],
        inputs: vec![],
        wires: vec![],
        gates: Vec::with_capacity(if generated { 0 } else { c.gates().len() }),
        corrections: Vec::with_capacity(if generated {
            setup.correction_blocks()
        } else {
            0
        }),
        encrypted_key: [0; 32],
        tag: [0; 32],
    };
    p.inputs = (0..c.policy().n())
        .map(|i| input_commitment(context, i, &tokens[i + 2]))
        .collect();
    let mut and_hash =
        crypto::HashTemplate::<256, 3>::new(b"css/generated-and/v1", &[context], [8, 32, 32])
            .expect("fixed gate frame");
    let mut or_hash =
        crypto::HashTemplate::<256, 3>::new(b"css/generated-or/v1", &[context], [8, 1, 32])
            .expect("fixed gate frame");
    for (j, g) in c.gates().iter().enumerate() {
        let v = c.base() + j;
        if generated {
            let token = match g.op {
                Op::And => {
                    and_hash.hash([&(v as u64).to_le_bytes(), &tokens[g.left], &tokens[g.right]])
                }
                Op::Or => or_hash.hash([&(v as u64).to_le_bytes(), &[0], &tokens[g.left]]),
            };
            if g.op == Op::Or {
                p.corrections.push(xor(
                    &token,
                    &or_hash.hash([&(v as u64).to_le_bytes(), &[1], &tokens[g.right]]),
                ));
            }
            tokens.push(token);
            continue;
        }
        let first = Zeroizing::new(match g.op {
            Op::And => hash(b"coins/mask", &[seed, context, &(v as u64).to_le_bytes()]),
            Op::Or => tokens[v],
        });
        let second = Zeroizing::new(match g.op {
            Op::And => xor(&first, &tokens[v]),
            Op::Or => tokens[v],
        });
        p.gates.push([
            xor(&first, &edge_pad(context, v, 0, g.left, &tokens[g.left])),
            xor(&second, &edge_pad(context, v, 1, g.right, &tokens[g.right])),
        ]);
    }
    if !matches!(digests, WireDigests::None) {
        let mut wire_hash = crypto::HashTemplate::<256, 2>::new(b"wire", &[context], [8, 32])
            .expect("fixed wire frame");
        p.wires = match digests {
            WireDigests::None => Vec::new(),
            WireDigests::All => tokens
                .iter()
                .enumerate()
                .map(|(v, t)| wire_hash.hash([&(v as u64).to_le_bytes(), t]))
                .collect(),
            // Do not hash omitted internal wires, even temporarily for the tag.
            WireDigests::Boundary(plan) => plan
                .wires()
                .iter()
                .map(|&v| wire_hash.hash([&(v as u64).to_le_bytes(), &tokens[v]]))
                .collect(),
        };
    }
    p.encrypted_key = xor(
        key,
        &hash(
            b"key",
            &[
                context,
                &(c.output() as u64).to_le_bytes(),
                &tokens[c.output()],
            ],
        ),
    );
    p.tag = match digests {
        WireDigests::Boundary(plan) => crypto::hash_with_tail(
            b"transcript/pvr-retained/v1",
            &[
                context,
                &plan.id(),
                &(c.output() as u64).to_le_bytes(),
                &tokens[c.output()],
            ],
            p.byte_len(),
            p.encoded_parts(&[0; 32]),
        ),
        _ => transcript_tag(context, &tokens[c.output()], &p),
    };
    (
        p,
        Zeroizing::new(if with_shares {
            tokens[2..c.base()].to_vec()
        } else {
            Vec::new()
        }),
    )
}
pub fn verify_input(
    setup: &Setup,
    context: &Block,
    public: &Public,
    party: usize,
    token: &Block,
) -> bool {
    verify_input_with_wires(setup, context, public, party, token, true)
}
pub(super) fn valid_shape(setup: &Setup, public: &Public, with_wires: bool) -> bool {
    valid_shape_count(
        setup,
        public,
        if with_wires { setup.circuit.nodes() } else { 0 },
    )
}
fn valid_shape_count(setup: &Setup, public: &Public, wire_count: usize) -> bool {
    public.inputs.len() == setup.circuit.policy().n()
        && match setup.backend() {
            Backend::Independent => {
                public.gates.len() == setup.circuit.gates().len() && public.corrections.is_empty()
            }
            Backend::GeneratedAnd0Or1 => {
                public.gates.is_empty() && public.corrections.len() == setup.correction_blocks()
            }
        }
        && public.wires.len() == wire_count
}
pub(super) fn verify_input_with_wires(
    setup: &Setup,
    context: &Block,
    public: &Public,
    party: usize,
    token: &Block,
    with_wires: bool,
) -> bool {
    party < setup.circuit.policy().n()
        && valid_shape(setup, public, with_wires)
        && equal(
            &input_commitment(context, party, token),
            &public.inputs[party],
        )
        && (!with_wires
            || equal(
                &wire_commitment(context, party + 2, token),
                &public.wires[party + 2],
            ))
}
/// Read-only public fields, shared by owned records and borrowed compact records.
pub(super) trait RecoveryFields {
    fn valid_shape(&self, setup: &Setup, with_wires: bool) -> bool;
    fn true_token(&self) -> Block;
    fn input(&self, party: usize) -> Block;
    fn wire(&self, wire: usize) -> Block;
    fn correction(&self, index: usize) -> Block;
    fn encrypted_key(&self) -> Block;
    fn tag(&self) -> Block;
    fn transcript_tag(&self, context: &Block, root: &Block) -> Block;
}
impl RecoveryFields for Public {
    fn valid_shape(&self, setup: &Setup, with_wires: bool) -> bool {
        valid_shape(setup, self, with_wires)
    }
    fn true_token(&self) -> Block {
        self.true_token
    }
    fn input(&self, party: usize) -> Block {
        self.inputs[party]
    }
    fn wire(&self, wire: usize) -> Block {
        self.wires[wire]
    }
    fn correction(&self, index: usize) -> Block {
        self.correction(index)
    }
    fn encrypted_key(&self) -> Block {
        self.encrypted_key
    }
    fn tag(&self) -> Block {
        self.tag
    }
    fn transcript_tag(&self, context: &Block, root: &Block) -> Block {
        transcript_tag(context, root, self)
    }
}
/// A recovered CSS key and the distinct inputs actually authenticated by recovery.
pub struct RecoveredKey {
    pub key: Zeroizing<Block>,
    pub inputs: Zeroizing<Vec<(usize, Block)>>,
}

/// Missing/invalid inputs do not imply bottom. Inputs are deduplicated before weighting.
pub fn reconstruct(
    setup: &Setup,
    context: &Block,
    public: &Public,
    shares: &[(usize, Block)],
) -> Result<Block> {
    reconstruct_with_wires(setup, context, public, shares, true)
}
pub(super) fn reconstruct_with_wires(
    setup: &Setup,
    context: &Block,
    public: &Public,
    shares: &[(usize, Block)],
    with_wires: bool,
) -> Result<Block> {
    reconstruct_fields(setup, context, public, shares.iter().copied(), with_wires)
        .map(|recovered| *recovered.key)
}
pub(super) fn reconstruct_fields(
    setup: &Setup,
    context: &Block,
    public: &impl RecoveryFields,
    shares: impl IntoIterator<Item = (usize, Block)>,
    with_wires: bool,
) -> Result<RecoveredKey> {
    let c = &setup.circuit;
    if !public.valid_shape(setup, with_wires) {
        return Err(Error::InvalidCommitment);
    }
    // Authenticate/deduplicate before allocating circuit-sized recovery buffers.
    let mut accepted = Zeroizing::new(vec![None; c.policy().n()]);
    for (i, token) in shares {
        if i < accepted.len()
            && accepted[i].is_none()
            && equal(&input_commitment(context, i, &token), &public.input(i))
            && (!with_wires
                || equal(
                    &wire_commitment(context, i + 2, &token),
                    &public.wire(i + 2),
                ))
        {
            accepted[i] = Some(token);
        }
    }
    if !c.policy().authorized(
        accepted
            .iter()
            .enumerate()
            .filter_map(|(i, t)| t.map(|_| i)),
    )? {
        return Err(Error::InsufficientShares);
    }
    let mut values = Zeroizing::new(vec![[0; 32]; c.nodes()]);
    let mut known = vec![false; c.nodes()];
    for (i, token) in accepted.iter().enumerate() {
        if let Some(token) = token {
            values[i + 2] = *token;
            known[i + 2] = true;
        }
    }
    values[1] = public.true_token();
    known[1] = true;
    if with_wires && !equal(&wire_commitment(context, 1, &values[1]), &public.wire(1)) {
        return Err(Error::InvalidCommitment);
    }
    let mut evaluator = GateEvaluator::new(setup, context);
    for (j, g) in c.gates().iter().enumerate() {
        let v = c.base() + j;
        if (g.op == Op::And && !(known[g.left] && known[g.right]))
            || (!known[g.left] && !known[g.right])
        {
            continue;
        }
        let choices = match g.op {
            Op::And => [3, 0],
            Op::Or => [u8::from(known[g.left]), 2 * u8::from(known[g.right])],
        };
        let mut candidate: Option<Block> = None;
        for branches in choices.into_iter().filter(|&b| b != 0) {
            let tokens = [
                if branches & 1 != 0 {
                    values[g.left]
                } else {
                    [0; 32]
                },
                if branches & 2 != 0 {
                    values[g.right]
                } else {
                    [0; 32]
                },
            ];
            let t = evaluator
                .evaluate(j, branches, &tokens, |i| public.correction(i))
                .ok_or(Error::InvalidCommitment)?;
            if candidate.is_some_and(|prev| !equal(&prev, &t)) {
                return Err(Error::InvalidCommitment);
            }
            candidate = Some(t);
        }
        let t = Zeroizing::new(candidate.ok_or(Error::InvalidCommitment)?);
        if with_wires && !equal(&wire_commitment(context, v, &t), &public.wire(v)) {
            return Err(Error::InvalidCommitment);
        }
        values[v] = *t;
        known[v] = true;
    }
    if !known[c.output()]
        || !equal(
            &public.transcript_tag(context, &values[c.output()]),
            &public.tag(),
        )
    {
        return Err(Error::InvalidCommitment);
    }
    let key = Zeroizing::new(xor(
        &public.encrypted_key(),
        &hash(
            b"key",
            &[
                context,
                &(c.output() as u64).to_le_bytes(),
                &values[c.output()],
            ],
        ),
    ));
    Ok(RecoveredKey {
        key,
        inputs: Zeroizing::new(
            accepted
                .iter()
                .enumerate()
                .filter_map(|(i, t)| t.map(|t| (i, t)))
                .collect(),
        ),
    })
}
