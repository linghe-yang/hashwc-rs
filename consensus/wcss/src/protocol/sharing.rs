//! Hash commitment sharing and reconstruction over the weighted circuit.
use super::circuit::{Circuit, Limits, Op};
use crypto::{Block, edge_pad, equal, hash, input_commitment, wire_commitment, xor};
use types::{Error, Policy, Result};
use zeroize::Zeroizing;

#[derive(Clone, Debug)]
pub struct Setup {
    pub circuit: Circuit,
    pub id: Block,
}
impl Setup {
    pub fn new(policy: Policy, limits: Limits) -> Result<Self> {
        let circuit = Circuit::build(policy, limits)?;
        let id = hash(b"setup/odd-even/p25519/token256", &[&circuit.encode()]);
        Ok(Self { circuit, id })
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
    pub encrypted_key: Block,
    pub tag: Block,
}
impl Public {
    pub fn encoded_len(setup: &Setup) -> usize {
        96 + 32 * (setup.circuit.policy().n() + setup.circuit.nodes())
            + 64 * setup.circuit.gates().len()
    }
    pub fn valid_shape(&self, setup: &Setup) -> bool {
        self.inputs.len() == setup.circuit.policy().n()
            && self.wires.len() == setup.circuit.nodes()
            && self.gates.len() == setup.circuit.gates().len()
    }
    pub fn byte_len(&self) -> usize {
        96 + 32 * (self.inputs.len() + self.wires.len()) + 64 * self.gates.len()
    }
    pub fn encoded_parts<'a>(&'a self, tag: &'a Block) -> impl Iterator<Item = &'a [u8]> {
        std::iter::once(&self.true_token)
            .chain(&self.inputs)
            .chain(&self.wires)
            .chain(self.gates.iter().flat_map(|pair| pair.iter()))
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
        if bytes.len() != Self::encoded_len(setup) {
            return Err(Error::Encoding);
        }
        let mut chunks = bytes.as_chunks::<32>().0.iter();
        let mut take = || -> Block { *chunks.next().expect("fixed layout validated") };
        Ok(Self {
            true_token: take(),
            inputs: (0..setup.circuit.policy().n()).map(|_| take()).collect(),
            wires: (0..setup.circuit.nodes()).map(|_| take()).collect(),
            gates: (0..setup.circuit.gates().len())
                .map(|_| [take(), take()])
                .collect(),
            encrypted_key: take(),
            tag: take(),
        })
    }
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
    let c = &setup.circuit;
    let tokens = Zeroizing::new(
        (0..c.nodes())
            .map(|v| hash(b"coins/token", &[seed, context, &(v as u64).to_le_bytes()]))
            .collect::<Vec<_>>(),
    );
    let mut p = Public {
        true_token: tokens[1],
        inputs: vec![],
        wires: vec![],
        gates: Vec::with_capacity(c.gates().len()),
        encrypted_key: [0; 32],
        tag: [0; 32],
    };
    p.inputs = (0..c.policy().n())
        .map(|i| input_commitment(context, i, &tokens[i + 2]))
        .collect();
    p.wires = tokens
        .iter()
        .enumerate()
        .map(|(v, t)| wire_commitment(context, v, t))
        .collect();
    for (j, g) in c.gates().iter().enumerate() {
        let v = c.base() + j;
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
    p.tag = transcript_tag(context, &tokens[c.output()], &p);
    (p, Zeroizing::new(tokens[2..c.base()].to_vec()))
}
pub fn verify_input(
    setup: &Setup,
    context: &Block,
    public: &Public,
    party: usize,
    token: &Block,
) -> bool {
    party < setup.circuit.policy().n()
        && public.valid_shape(setup)
        && equal(
            &input_commitment(context, party, token),
            &public.inputs[party],
        )
        && equal(
            &wire_commitment(context, party + 2, token),
            &public.wires[party + 2],
        )
}
/// Missing/invalid inputs do not imply bottom. Inputs are deduplicated before weighting.
pub fn reconstruct(
    setup: &Setup,
    context: &Block,
    public: &Public,
    shares: &[(usize, Block)],
) -> Result<Block> {
    let c = &setup.circuit;
    if !public.valid_shape(setup) {
        return Err(Error::InvalidCommitment);
    }
    let mut values = Zeroizing::new(vec![[0; 32]; c.nodes()]);
    let mut known = vec![false; c.nodes()];
    for &(i, token) in shares {
        if verify_input(setup, context, public, i, &token) {
            values[i + 2] = token;
            known[i + 2] = true;
        }
    }
    if !c
        .policy()
        .authorized((0..c.policy().n()).filter(|i| known[i + 2]))?
    {
        return Err(Error::InsufficientShares);
    }
    values[1] = public.true_token;
    known[1] = true;
    if !equal(&wire_commitment(context, 1, &values[1]), &public.wires[1]) {
        return Err(Error::InvalidCommitment);
    }
    for (j, g) in c.gates().iter().enumerate() {
        let v = c.base() + j;
        if (g.op == Op::And && !(known[g.left] && known[g.right]))
            || (!known[g.left] && !known[g.right])
        {
            continue;
        }
        let mut candidate = None;
        for (branch, src) in [g.left, g.right].into_iter().enumerate() {
            if known[src] {
                let t = xor(
                    &public.gates[j][branch],
                    &edge_pad(context, v, branch, src, &values[src]),
                );
                candidate = Some(match (g.op, candidate) {
                    (Op::And, Some(prev)) => xor(&prev, &t),
                    (Op::Or, Some(prev)) => {
                        if !equal(&prev, &t) {
                            return Err(Error::InvalidCommitment);
                        }
                        prev
                    }
                    (_, None) => t,
                });
            }
        }
        let t = Zeroizing::new(candidate.ok_or(Error::InvalidCommitment)?);
        if !equal(&wire_commitment(context, v, &t), &public.wires[v]) {
            return Err(Error::InvalidCommitment);
        }
        values[v] = *t;
        known[v] = true;
    }
    if !known[c.output()]
        || !equal(
            &transcript_tag(context, &values[c.output()], public),
            &public.tag,
        )
    {
        return Err(Error::InvalidCommitment);
    }
    Ok(xor(
        &public.encrypted_key,
        &hash(
            b"key",
            &[
                context,
                &(c.output() as u64).to_le_bytes(),
                &values[c.output()],
            ],
        ),
    ))
}
