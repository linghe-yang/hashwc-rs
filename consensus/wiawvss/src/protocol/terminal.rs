//! Bounded publicly verifiable terminals for the full-public-transcript wiAwVSS.
//! The common transcript is already authenticated by WRBC: no Merkle field paths are needed.
use crate::{Context, Opening, PrivateShare, Public, ax};
use crypto::{Block, edge_pad, equal, hash, input_commitment, wire_commitment, xor};
use types::{Error, Result};
use wcss::{Op, Setup};
use zeroize::Zeroizing;

#[derive(Clone, PartialEq, Eq)]
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
}
impl Terminal {
    pub const MAX_BYTES: usize = 106;
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
        }
        b
    }
    pub fn decode(public: &Public, b: &[u8]) -> Result<Self> {
        if !(33..=Self::MAX_BYTES).contains(&b.len()) || b[..32] != public.digest() {
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
            _ => return Err(Error::Encoding),
        })
    }
}
fn candidate(context: &Context, p: &Public, output: usize, token: &Block) -> Opening {
    let k = Zeroizing::new(xor(
        &p.base.encrypted_key,
        &hash(
            b"key",
            &[&context.id(), &(output as u64).to_le_bytes(), token],
        ),
    ));
    Opening {
        message: xor(&p.ciphertext, &hash(b"AX/mask", &[&*k, b"msg"])),
        randomness: xor(&p.randomness_ciphertext, &hash(b"AX/mask", &[&*k, b"rnd"])),
    }
}
/// Verification never treats malformed evidence as bottom.
pub fn verify(setup: &Setup, c: &Context, p: &Public, t: &Terminal) -> bool {
    if c.validate(setup).is_err()
        || p.setup_id != setup.id()
        || p.context_id != c.id()
        || !p.base.valid_shape(setup)
    {
        return false;
    }
    let circuit = setup.circuit();
    match t {
        Terminal::Success(o) => ax::verify_opening(setup, c, p, o),
        Terminal::TrueFault => !equal(
            &wire_commitment(&c.id(), 1, &p.base.true_token),
            &p.base.wires[1],
        ),
        Terminal::InputFault { party, token } => {
            *party < circuit.policy().n()
                && equal(
                    &input_commitment(&c.id(), *party, token),
                    &p.base.inputs[*party],
                )
                && !equal(
                    &wire_commitment(&c.id(), party + 2, token),
                    &p.base.wires[party + 2],
                )
        }
        Terminal::GateFault {
            wire,
            branches,
            tokens,
        } => {
            if *wire < circuit.base() || *wire >= circuit.nodes() {
                return false;
            }
            let g = circuit.gates()[wire - circuit.base()];
            if !(match g.op {
                Op::And => *branches == 3,
                Op::Or => matches!(*branches, 1 | 2),
            }) {
                return false;
            }
            let mut output = [0; 32];
            for (j, src) in [g.left, g.right].into_iter().enumerate() {
                if branches & (1 << j) == 0 {
                    if tokens[j] != [0; 32] {
                        return false;
                    }
                    continue;
                }
                if !equal(
                    &wire_commitment(&c.id(), src, &tokens[j]),
                    &p.base.wires[src],
                ) {
                    return false;
                }
                output = xor(
                    &output,
                    &xor(
                        &p.base.gates[wire - circuit.base()][j],
                        &edge_pad(&c.id(), *wire, j, src, &tokens[j]),
                    ),
                );
            }
            !equal(
                &wire_commitment(&c.id(), *wire, &output),
                &p.base.wires[*wire],
            )
        }
        Terminal::RootFault { token } => {
            equal(
                &wire_commitment(&c.id(), circuit.output(), token),
                &p.base.wires[circuit.output()],
            ) && !ax::verify_opening(setup, c, p, &candidate(c, p, circuit.output(), token))
        }
    }
}
/// Only the frozen outer protocol may publish the returned token-dependent evidence.
pub fn recover(
    setup: &Setup,
    c: &Context,
    p: &Public,
    shares: &[PrivateShare],
) -> Result<Terminal> {
    if c.validate(setup).is_err()
        || p.setup_id != setup.id()
        || p.context_id != c.id()
        || !p.base.valid_shape(setup)
    {
        return Err(Error::InvalidCommitment);
    }
    let circuit = setup.circuit();
    let mut values = Zeroizing::new(vec![[0; 32]; circuit.nodes()]);
    let mut known = vec![false; circuit.nodes()];
    if !equal(
        &wire_commitment(&c.id(), 1, &p.base.true_token),
        &p.base.wires[1],
    ) {
        return Ok(Terminal::TrueFault);
    }
    values[1] = p.base.true_token;
    known[1] = true;
    for s in shares {
        if s.party >= circuit.policy().n()
            || s.context_id != c.id()
            || s.setup_id != setup.id()
            || !equal(
                &input_commitment(&c.id(), s.party, &s.token),
                &p.base.inputs[s.party],
            )
        {
            continue;
        }
        if !equal(
            &wire_commitment(&c.id(), s.party + 2, &s.token),
            &p.base.wires[s.party + 2],
        ) {
            return Ok(Terminal::InputFault {
                party: s.party,
                token: s.token,
            });
        }
        values[s.party + 2] = s.token;
        known[s.party + 2] = true;
    }
    if !circuit
        .policy()
        .authorized((0..circuit.policy().n()).filter(|i| known[i + 2]))?
    {
        return Err(Error::InsufficientShares);
    }
    for (index, g) in circuit.gates().iter().enumerate() {
        let wire = circuit.base() + index;
        let available = (known[g.left] as u8) | ((known[g.right] as u8) << 1);
        let choices = match g.op {
            Op::And => {
                if available == 3 {
                    vec![3]
                } else {
                    vec![]
                }
            }
            Op::Or => (0..2)
                .filter(|j| available & (1 << j) != 0)
                .map(|j| 1 << j)
                .collect(),
        };
        for branches in choices {
            let mut output = [0; 32];
            let mut tokens = [[0; 32]; 2];
            for (j, src) in [g.left, g.right].into_iter().enumerate() {
                if branches & (1 << j) != 0 {
                    tokens[j] = values[src];
                    output = xor(
                        &output,
                        &xor(
                            &p.base.gates[index][j],
                            &edge_pad(&c.id(), wire, j, src, &tokens[j]),
                        ),
                    );
                }
            }
            if !equal(
                &wire_commitment(&c.id(), wire, &output),
                &p.base.wires[wire],
            ) {
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
    if !known[circuit.output()] {
        return Err(Error::InvalidCommitment);
    }
    let opening = candidate(c, p, circuit.output(), &values[circuit.output()]);
    if ax::verify_opening(setup, c, p, &opening) {
        Ok(Terminal::Success(opening))
    } else {
        Ok(Terminal::RootFault {
            token: values[circuit.output()],
        })
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
        })
    }
}
