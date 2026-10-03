use num_bigint::BigUint;
use std::collections::BTreeMap;
use types::{Error, Policy, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Op {
    And,
    Or,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gate {
    pub op: Op,
    pub left: usize,
    pub right: usize,
}
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub parties: usize,
    pub bit_layers: u64,
    pub gates: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            parties: 4096,
            bit_layers: 4096,
            gates: 4_000_000,
        }
    }
}
#[derive(Clone, Debug)]
pub struct Circuit {
    pub policy: Policy,
    pub gates: Vec<Gate>,
    pub output: usize,
}
impl Circuit {
    pub fn build(policy: Policy, limits: Limits) -> Result<Self> {
        if policy.n() > limits.parties {
            return Err(Error::ResourceLimit("parties"));
        }
        let d = policy.total().bits();
        if d > limits.bit_layers {
            return Err(Error::ResourceLimit("weight bit layers"));
        }
        let offset = (BigUint::from(1u8) << d as usize) - policy.threshold();
        let mut b = Builder {
            circuit: Self {
                policy,
                gates: vec![],
                output: 0,
            },
            intern: BTreeMap::new(),
            limit: limits.gates,
        };
        let mut carry = vec![];
        for bit in 0..d {
            let mut refs: Vec<_> = b
                .circuit
                .policy
                .weights()
                .iter()
                .enumerate()
                .filter(|(_, w)| w.bit(bit))
                .map(|(i, _)| i + 2)
                .collect();
            refs.append(&mut carry);
            if offset.bit(bit) {
                refs.push(1);
            }
            if refs.len() > 1 {
                let width = refs
                    .len()
                    .checked_next_power_of_two()
                    .ok_or(Error::ResourceLimit("sort width"))?;
                b.sort(&mut refs, 0, width)?;
            }
            // Ascending sorter: every second position from the right is unary carry.
            carry = refs.iter().rev().skip(1).step_by(2).copied().collect();
        }
        b.circuit.output = carry.first().copied().unwrap_or(0);
        Ok(b.prune())
    }
    pub fn policy(&self) -> &Policy {
        &self.policy
    }
    pub fn gates(&self) -> &[Gate] {
        &self.gates
    }
    pub fn output(&self) -> usize {
        self.output
    }
    pub fn base(&self) -> usize {
        self.policy.n() + 2
    }
    pub fn nodes(&self) -> usize {
        self.base() + self.gates.len()
    }
    pub fn evaluate(&self, members: &[usize]) -> Result<bool> {
        let mut wires = vec![false; self.nodes()];
        wires[1] = true;
        for &i in members {
            if i >= self.policy.n() {
                return Err(Error::Parameters("unknown party"));
            }
            wires[i + 2] = true;
        }
        for (j, g) in self.gates.iter().enumerate() {
            wires[self.base() + j] = match g.op {
                Op::And => wires[g.left] && wires[g.right],
                Op::Or => wires[g.left] || wires[g.right],
            };
        }
        Ok(wires[self.output])
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = self.policy.encode();
        bytes.extend_from_slice(&(self.output as u64).to_le_bytes());
        bytes.extend_from_slice(&(self.gates.len() as u64).to_le_bytes());
        for g in &self.gates {
            bytes.push(match g.op {
                Op::And => 0,
                Op::Or => 1,
            });
            bytes.extend_from_slice(&(g.left as u64).to_le_bytes());
            bytes.extend_from_slice(&(g.right as u64).to_le_bytes());
        }
        bytes
    }
}
struct Builder {
    pub circuit: Circuit,
    pub intern: BTreeMap<(Op, usize, usize), usize>,
    pub limit: usize,
}
impl Builder {
    fn gate(&mut self, op: Op, a: usize, b: usize) -> Result<usize> {
        let (a, b) = if a > b { (b, a) } else { (a, b) };
        if a == b {
            return Ok(a);
        }
        match (op, a) {
            (Op::And, 0) => return Ok(0),
            (Op::And, 1) => return Ok(b),
            (Op::Or, 0) => return Ok(b),
            (Op::Or, 1) => return Ok(1),
            _ => {}
        }
        if let Some(&node) = self.intern.get(&(op, a, b)) {
            return Ok(node);
        }
        if self.circuit.gates.len() >= self.limit {
            return Err(Error::ResourceLimit("gates"));
        }
        let node = self.circuit.nodes();
        self.circuit.gates.push(Gate {
            op,
            left: a,
            right: b,
        });
        self.intern.insert((op, a, b), node);
        Ok(node)
    }
    fn compare(&mut self, refs: &mut [usize], i: usize, j: usize) -> Result<()> {
        // Omitted wires are +infinity padding, as in the reference Batcher network.
        if j < refs.len() {
            let (a, b) = (refs[i], refs[j]);
            refs[i] = self.gate(Op::And, a, b)?;
            refs[j] = self.gate(Op::Or, a, b)?;
        }
        Ok(())
    }
    fn merge(
        &mut self,
        refs: &mut [usize],
        start: usize,
        size: usize,
        stride: usize,
    ) -> Result<()> {
        let double = 2 * stride;
        if double < size {
            self.merge(refs, start, size, double)?;
            self.merge(refs, start + stride, size, double)?;
            for i in (start + stride..start + size - stride).step_by(double) {
                self.compare(refs, i, i + stride)?;
            }
        } else {
            self.compare(refs, start, start + stride)?;
        }
        Ok(())
    }
    fn sort(&mut self, refs: &mut [usize], start: usize, size: usize) -> Result<()> {
        if size > 1 {
            self.sort(refs, start, size / 2)?;
            self.sort(refs, start + size / 2, size / 2)?;
            self.merge(refs, start, size, 1)?;
        }
        Ok(())
    }
    fn prune(mut self) -> Circuit {
        let base = self.circuit.base();
        let mut live = vec![false; self.circuit.nodes()];
        live[self.circuit.output] = true;
        for (j, g) in self.circuit.gates.iter().enumerate().rev() {
            if live[base + j] {
                live[g.left] = true;
                live[g.right] = true;
            }
        }
        let mut remap: Vec<_> = (0..base).collect();
        let mut gates = vec![];
        for (j, g) in self.circuit.gates.iter().enumerate() {
            if live[base + j] {
                remap.push(base + gates.len());
                gates.push(Gate {
                    op: g.op,
                    left: remap[g.left],
                    right: remap[g.right],
                });
            } else {
                remap.push(0);
            }
        }
        self.circuit.output = remap[self.circuit.output];
        self.circuit.gates = gates;
        self.circuit
    }
}
