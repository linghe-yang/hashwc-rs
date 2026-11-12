//! Local terminal predicates evaluated by a recoverer against its decoded bulk.
//! Network certificates authenticate the required fields in certified.rs.
use crate::{Context, Opening, PrivateShare, Public, ax};
use crypto::{Block, equal, hash, input_commitment, wire_commitment, xor};
use types::{Error, Result};
use wcss::{Op, Setup};
use zeroize::Zeroizing;

#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Terminal {
    Success(Opening),
    TrueFault,
    InputFault {
        party: usize,
        token: Block,
    },
    GateFault {
        wire: usize,
        branches: u8,
        tokens: [Block; 2],
    },
    RootFault {
        token: Block,
    },
    ModuleFault {
        module: usize,
        output: usize,
        inputs: Vec<(usize, Block)>,
    },
}
impl Terminal {
    pub const MAX_BYTES: usize = 106;
    pub fn max_bytes(public: &Public) -> usize {
        public.boundary().map_or(Self::MAX_BYTES, |p| {
            Self::MAX_BYTES.max(57 + 40 * p.maximum_inputs())
        })
    }
    pub fn encode(&self, public: &Public) -> Vec<u8> {
        let mut b = public.digest().to_vec();
        match self {
            Self::Success(o) => {
                b.push(0);
                b.extend_from_slice(&o.message);
                b.extend_from_slice(&o.randomness);
            }
            Self::TrueFault => b.push(1),
            Self::InputFault { party, token } => {
                b.push(2);
                b.extend_from_slice(&(*party as u64).to_le_bytes());
                b.extend_from_slice(token);
            }
            Self::GateFault {
                wire,
                branches,
                tokens,
            } => {
                b.push(3);
                b.extend_from_slice(&(*wire as u64).to_le_bytes());
                b.push(*branches);
                for t in tokens {
                    b.extend_from_slice(t);
                }
            }
            Self::RootFault { token } => {
                b.push(4);
                b.extend_from_slice(token);
            }
            Self::ModuleFault {
                module,
                output,
                inputs,
            } => {
                b.push(5);
                for v in [*module, *output, inputs.len()] {
                    b.extend_from_slice(&(v as u64).to_le_bytes());
                }
                for (wire, token) in inputs {
                    b.extend_from_slice(&(*wire as u64).to_le_bytes());
                    b.extend_from_slice(token);
                }
            }
        }
        b
    }
    pub fn decode(public: &Public, b: &[u8]) -> Result<Self> {
        if !(33..=Self::max_bytes(public)).contains(&b.len()) || b[..32] != public.digest() {
            return Err(Error::Encoding);
        }
        let index = || {
            usize::try_from(u64::from_le_bytes(b[33..41].try_into().unwrap()))
                .map_err(|_| Error::Encoding)
        };
        Ok(match (b[32], b.len()) {
            (0, 97) => Self::Success(Opening {
                message: b[33..65].try_into().unwrap(),
                randomness: b[65..97].try_into().unwrap(),
            }),
            (1, 33) => Self::TrueFault,
            (2, 73) => Self::InputFault {
                party: index()?,
                token: b[41..73].try_into().unwrap(),
            },
            (3, 106) => Self::GateFault {
                wire: index()?,
                branches: b[41],
                tokens: [
                    b[42..74].try_into().unwrap(),
                    b[74..106].try_into().unwrap(),
                ],
            },
            (4, 65) => Self::RootFault {
                token: b[33..65].try_into().unwrap(),
            },
            (5, len) if len >= 57 => {
                let number = |start| {
                    usize::try_from(u64::from_le_bytes(b[start..start + 8].try_into().unwrap()))
                        .map_err(|_| Error::Encoding)
                };
                let module = number(33)?;
                let output = number(41)?;
                let count = number(49)?;
                let m = public
                    .boundary()
                    .and_then(|p| p.modules().get(module))
                    .ok_or(Error::Encoding)?;
                if count > m.inputs.len()
                    || count.checked_mul(40).and_then(|n| n.checked_add(57)) != Some(len)
                    || m.outputs.binary_search(&output).is_err()
                {
                    return Err(Error::Encoding);
                }
                let mut inputs = Vec::with_capacity(count);
                for i in 0..count {
                    let start = 57 + 40 * i;
                    let wire = number(start)?;
                    if m.inputs.binary_search(&wire).is_err()
                        || inputs.last().is_some_and(|x: &(usize, Block)| x.0 >= wire)
                    {
                        return Err(Error::Encoding);
                    }
                    inputs.push((wire, b[start + 8..start + 40].try_into().unwrap()));
                }
                Self::ModuleFault {
                    module,
                    output,
                    inputs,
                }
            }
            _ => return Err(Error::Encoding),
        })
    }
}
pub fn candidate(context: &Context, p: &Public, output: usize, token: &Block) -> Opening {
    candidate_fields(
        context,
        output,
        token,
        &p.base.encrypted_key,
        &p.ciphertext,
        &p.randomness_ciphertext,
    )
}
pub fn candidate_fields(
    context: &Context,
    output: usize,
    token: &Block,
    encrypted_key: &Block,
    ciphertext: &Block,
    randomness_ciphertext: &Block,
) -> Opening {
    let k = Zeroizing::new(xor(
        encrypted_key,
        &hash(
            b"key",
            &[&context.id(), &(output as u64).to_le_bytes(), token],
        ),
    ));
    Opening {
        message: xor(ciphertext, &hash(b"AX/mask", &[&*k, b"msg"])),
        randomness: xor(randomness_ciphertext, &hash(b"AX/mask", &[&*k, b"rnd"])),
    }
}
/// Verification never treats malformed evidence as bottom.
pub fn verify(setup: &Setup, c: &Context, p: &Public, t: &Terminal) -> bool {
    if p.validate(setup, c).is_err() {
        return false;
    }
    match t {
        Terminal::Success(o) => ax::verify_opening(setup, c, p, o),
        Terminal::RootFault { token } => {
            let output = setup.circuit().output();
            equal(&wire_commitment(&c.id(), output, token), &p.wire(output))
                && !ax::verify_opening(setup, c, p, &candidate(c, p, output, token))
        }
        _ => verify_local_fault(setup, c, p, t),
    }
}
/// Access only fields required by a gate or module fault predicate.
/// Network callers must authenticate all requested fields before using this trait.
pub trait SemanticFields {
    fn true_token(&self) -> Block;
    fn input(&self, party: usize) -> Block;
    fn wire(&self, wire: usize) -> Block;
    fn correction(&self, index: usize) -> Block;
}
impl SemanticFields for Public {
    fn true_token(&self) -> Block {
        self.base.true_token
    }
    fn input(&self, party: usize) -> Block {
        self.base.inputs[party]
    }
    fn wire(&self, wire: usize) -> Block {
        self.wire(wire)
    }
    fn correction(&self, index: usize) -> Block {
        self.base.correction(index)
    }
}
pub fn verify_local_fault(
    setup: &Setup,
    c: &Context,
    fields: &impl SemanticFields,
    t: &Terminal,
) -> bool {
    let circuit = setup.circuit();
    match t {
        Terminal::TrueFault => !equal(
            &wire_commitment(&c.id(), 1, &fields.true_token()),
            &fields.wire(1),
        ),
        Terminal::InputFault { party, token } => {
            *party < circuit.policy().n()
                && equal(
                    &input_commitment(&c.id(), *party, token),
                    &fields.input(*party),
                )
                && !equal(
                    &wire_commitment(&c.id(), party + 2, token),
                    &fields.wire(party + 2),
                )
        }
        Terminal::GateFault {
            wire,
            branches,
            tokens,
        } => {
            if setup.boundary().is_some() || *wire < circuit.base() || *wire >= circuit.nodes() {
                return false;
            }
            let g = circuit.gates()[wire - circuit.base()];
            if !(match g.op {
                Op::And => *branches == 3,
                Op::Or => matches!(*branches, 1 | 2),
            }) {
                return false;
            }
            for (j, src) in [g.left, g.right].into_iter().enumerate() {
                if branches & (1 << j) == 0 {
                    if tokens[j] != [0; 32] {
                        return false;
                    }
                    continue;
                }
                if !equal(
                    &wire_commitment(&c.id(), src, &tokens[j]),
                    &fields.wire(src),
                ) {
                    return false;
                }
            }
            let Some(output) = wcss::evaluate_gate(
                setup,
                &c.id(),
                wire - circuit.base(),
                *branches,
                tokens,
                |i| fields.correction(i),
            ) else {
                return false;
            };
            !equal(
                &wire_commitment(&c.id(), *wire, &output),
                &fields.wire(*wire),
            )
        }
        Terminal::ModuleFault {
            module,
            output,
            inputs,
        } => super::modules::verify_fault(setup, c, fields, *module, *output, inputs),
        Terminal::Success(_) | Terminal::RootFault { .. } => false,
    }
}
/// Only the frozen outer protocol may publish the returned token-dependent evidence.
pub fn recover(
    setup: &Setup,
    c: &Context,
    p: &Public,
    shares: &[PrivateShare],
) -> Result<Terminal> {
    recover_bounded(setup, c, p, shares, 256)
}
pub fn recover_bounded(
    setup: &Setup,
    c: &Context,
    p: &Public,
    shares: &[PrivateShare],
    bits: usize,
) -> Result<Terminal> {
    recover_bounded_iter(setup, c, p, shares.iter(), bits)
}
/// Borrow recovery tokens directly; no copies of secret shares are required.
pub fn recover_bounded_iter<'a>(
    setup: &Setup,
    c: &Context,
    p: &impl super::view::RecoveryPublic,
    shares: impl IntoIterator<Item = &'a PrivateShare>,
    bits: usize,
) -> Result<Terminal> {
    p.validate(setup, c)?;
    let circuit = setup.circuit();
    let mut accepted = vec![None; circuit.policy().n()];
    if !equal(&wire_commitment(&c.id(), 1, &p.true_token()), &p.wire(1)) {
        return Ok(Terminal::TrueFault);
    }
    for s in shares {
        if s.party >= circuit.policy().n()
            || s.context_id != c.id()
            || s.setup_id != setup.id()
            || !equal(
                &input_commitment(&c.id(), s.party, &s.token),
                &p.input(s.party),
            )
        {
            continue;
        }
        if !equal(
            &wire_commitment(&c.id(), s.party + 2, &s.token),
            &p.wire(s.party + 2),
        ) {
            return Ok(Terminal::InputFault {
                party: s.party,
                token: s.token,
            });
        }
        accepted[s.party] = Some(s);
    }
    if !circuit
        .policy()
        .authorized((0..circuit.policy().n()).filter(|&i| accepted[i].is_some()))?
    {
        return Err(Error::InsufficientShares);
    }
    evaluate(setup, c, p, accepted.into_iter().flatten(), bits)
}
/// Inputs have been authenticated and their unique weight has reached T.
pub(crate) fn evaluate<'a>(
    setup: &Setup,
    c: &Context,
    p: &impl super::view::RecoveryPublic,
    accepted: impl IntoIterator<Item = &'a PrivateShare>,
    bits: usize,
) -> Result<Terminal> {
    let circuit = setup.circuit();
    // Allocate the circuit-sized scratch only after all input fault checks and authorization.
    let mut values = Zeroizing::new(vec![[0; 32]; circuit.nodes()]);
    let mut known = vec![false; circuit.nodes()];
    values[1] = p.true_token();
    known[1] = true;
    for s in accepted {
        values[s.party + 2] = s.token;
        known[s.party + 2] = true;
    }
    let mut evaluator = wcss::GateEvaluator::new(setup, &c.id());
    if let Some(plan) = setup.boundary() {
        let max_gates = plan
            .modules()
            .iter()
            .map(|m| m.gates.len())
            .max()
            .unwrap_or(0);
        let max_inputs = plan
            .modules()
            .iter()
            .map(|m| m.inputs.len())
            .max()
            .unwrap_or(0);
        let mut local = Zeroizing::new(vec![None; max_gates]);
        let mut inputs = Zeroizing::new(Vec::with_capacity(max_inputs));
        for (module, m) in plan.modules().iter().enumerate() {
            zeroize::Zeroize::zeroize(&mut *inputs);
            inputs.clear();
            inputs.extend(
                m.inputs
                    .iter()
                    .filter(|&&wire| known[wire])
                    .map(|&wire| (wire, values[wire])),
            );
            super::modules::evaluate_into(
                setup,
                p,
                m,
                &inputs,
                &mut evaluator,
                &mut local[..m.gates.len()],
            );
            for &wire in &m.outputs {
                let Some(token) = local[wire - circuit.base() - m.gates.start] else {
                    continue;
                };
                if !equal(&wire_commitment(&c.id(), wire, &token), &p.wire(wire)) {
                    return Ok(Terminal::ModuleFault {
                        module,
                        output: wire,
                        inputs: inputs.to_vec(),
                    });
                }
                values[wire] = token;
                known[wire] = true;
            }
        }
    } else {
        for (index, g) in circuit.gates().iter().enumerate() {
            let wire = circuit.base() + index;
            let available = (known[g.left] as u8) | ((known[g.right] as u8) << 1);
            let choices = match g.op {
                Op::And => [if available == 3 { 3 } else { 0 }, 0],
                Op::Or => [available & 1, available & 2],
            };
            for branches in choices.into_iter().filter(|&branches| branches != 0) {
                let mut tokens = [[0; 32]; 2];
                for (j, src) in [g.left, g.right].into_iter().enumerate() {
                    if branches & (1 << j) != 0 {
                        tokens[j] = values[src];
                    }
                }
                let output = evaluator
                    .evaluate(index, branches, &tokens, |i| p.correction(i))
                    .ok_or(Error::InvalidCommitment)?;
                if !equal(&wire_commitment(&c.id(), wire, &output), &p.wire(wire)) {
                    return Ok(Terminal::GateFault {
                        wire,
                        branches,
                        tokens,
                    });
                }
                if known[wire] && !equal(&values[wire], &output) {
                    return Err(Error::InvalidCommitment);
                }
                values[wire] = output;
                known[wire] = true;
            }
        }
    }
    if !known[circuit.output()] {
        return Err(Error::InvalidCommitment);
    }
    let root = Zeroizing::new(values[circuit.output()]);
    let opening = p.candidate(c, circuit.output(), &root);
    // Reconstruction and full AX regeneration need not retain two simultaneous
    // circuit-sized secret arrays. The root suffices for a possible fault.
    drop(values);
    drop(known);
    drop(evaluator);
    if p.verify_opening(setup, c, &opening) && super::certified::in_range(&opening.message, bits) {
        Ok(Terminal::Success(opening))
    } else {
        Ok(Terminal::RootFault { token: *root })
    }
}

impl std::fmt::Debug for Terminal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Success(_) => "Success([REDACTED])",
            Self::TrueFault => "TrueFault",
            Self::InputFault { .. } => "InputFault([REDACTED])",
            Self::GateFault { .. } => "GateFault([REDACTED])",
            Self::RootFault { .. } => "RootFault([REDACTED])",
            Self::ModuleFault { .. } => "ModuleFault([REDACTED])",
        })
    }
}
