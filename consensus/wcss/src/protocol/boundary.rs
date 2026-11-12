//! Deterministic four-column partition of the unchanged, pruned circuit DAG.
use super::{Circuit, Op};
use crypto::Block;
use std::{collections::BTreeSet, ops::Range};
use types::{Error, Result};

pub const COLUMNS_PER_MODULE: u64 = 4;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Module {
    /// Original normalized bit column divided by four; empty groups are omitted.
    pub column_group: u64,
    pub gates: Range<usize>,
    pub corrections: Range<usize>,
    pub inputs: Vec<usize>,
    pub outputs: Vec<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    id: Block,
    modules: Vec<Module>,
    wires: Vec<usize>,
    indices: Vec<Option<usize>>,
}
impl Plan {
    pub fn new(c: &Circuit) -> Result<Self> {
        let bad = || Error::Parameters("invalid module provenance");
        if c.gate_columns.len() != c.gates().len()
            || c.gate_columns.windows(2).any(|w| w[0] > w[1])
            || c.output() >= c.nodes()
        {
            return Err(bad());
        }
        let mut modules: Vec<Module> = vec![];
        let mut owners = vec![];
        let mut corrections = 0;
        for (i, (g, column)) in c.gates().iter().zip(&c.gate_columns).enumerate() {
            if g.left >= c.base() + i || g.right >= c.base() + i {
                return Err(bad());
            }
            let group = column / COLUMNS_PER_MODULE;
            if modules.last().is_none_or(|m| m.column_group != group) {
                modules.push(Module {
                    column_group: group,
                    gates: i..i,
                    corrections: corrections..corrections,
                    inputs: vec![],
                    outputs: vec![],
                });
            }
            corrections += usize::from(g.op == Op::Or);
            let module = modules.last_mut().unwrap();
            module.gates.end = i + 1;
            module.corrections.end = corrections;
            owners.push(modules.len() - 1);
        }
        let mut inputs = vec![BTreeSet::new(); modules.len()];
        let mut outputs = vec![BTreeSet::new(); modules.len()];
        for (i, g) in c.gates().iter().enumerate() {
            let owner = owners[i];
            for src in [g.left, g.right] {
                if src < c.base() {
                    inputs[owner].insert(src);
                } else if owners[src - c.base()] != owner {
                    let previous = owners[src - c.base()];
                    if previous >= owner {
                        return Err(bad());
                    }
                    inputs[owner].insert(src);
                    outputs[previous].insert(src);
                }
            }
        }
        if c.output() >= c.base() {
            outputs[owners[c.output() - c.base()]].insert(c.output());
        }
        let mut retained: BTreeSet<usize> = (0..c.base()).collect();
        for (i, module) in modules.iter_mut().enumerate() {
            module.inputs = inputs[i].iter().copied().collect();
            module.outputs = outputs[i].iter().copied().collect();
            retained.extend(&module.outputs);
        }
        let wires: Vec<_> = retained.into_iter().collect();
        let mut indices = vec![None; c.nodes()];
        for (index, &wire) in wires.iter().enumerate() {
            indices[wire] = Some(index);
        }
        let mut provenance = COLUMNS_PER_MODULE.to_le_bytes().to_vec();
        provenance.extend_from_slice(&(c.gate_columns.len() as u64).to_le_bytes());
        for col in &c.gate_columns {
            provenance.extend_from_slice(&col.to_le_bytes());
        }
        let id = crypto::hash(b"pvr/four-column-manifest/v1", &[&c.encode(), &provenance]);
        Ok(Self {
            id,
            modules,
            wires,
            indices,
        })
    }
    pub fn id(&self) -> Block {
        self.id
    }
    pub fn modules(&self) -> &[Module] {
        &self.modules
    }
    /// Includes both constants, every original input, cross-module sources and root.
    pub fn wires(&self) -> &[usize] {
        &self.wires
    }
    pub fn index(&self, wire: usize) -> Option<usize> {
        self.indices.get(wire).copied().flatten()
    }
    pub fn maximum_inputs(&self) -> usize {
        self.modules
            .iter()
            .map(|m| m.inputs.len())
            .max()
            .unwrap_or(0)
    }
}
