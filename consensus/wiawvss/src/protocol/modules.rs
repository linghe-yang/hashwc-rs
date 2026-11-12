//! Partial-input evaluation of a public four-column module. Missing entrances
//! mean unavailable labels, never authenticated false values.
use crate::{Context, terminal::SemanticFields};
use crypto::{Block, equal, wire_commitment};
use wcss::{Op, Setup, boundary::Module};
use zeroize::Zeroizing;

/// Cheap canonical structure check, performed before any field access.
pub fn witness<'a>(
    setup: &'a Setup,
    module: usize,
    output: usize,
    inputs: &[(usize, Block)],
) -> Option<&'a Module> {
    let m = setup.boundary()?.modules().get(module)?;
    if inputs.len() > m.inputs.len()
        || inputs.windows(2).any(|w| w[0].0 >= w[1].0)
        || m.outputs.binary_search(&output).is_err()
        || inputs
            .iter()
            .any(|(wire, _)| m.inputs.binary_search(wire).is_err())
    {
        return None;
    }
    Some(m)
}

/// Caller checks the manifest membership and authenticates the supplied entries.
/// Uses scratch only proportional to this module, not the entire circuit.
pub(crate) fn evaluate(
    setup: &Setup,
    c: &Context,
    fields: &impl SemanticFields,
    m: &Module,
    inputs: &[(usize, Block)],
) -> Zeroizing<Vec<Option<Block>>> {
    let mut values = Zeroizing::new(vec![None; m.gates.len()]);
    let mut evaluator = wcss::GateEvaluator::new(setup, &c.id());
    evaluate_into(setup, fields, m, inputs, &mut evaluator, &mut values);
    values
}
/// Reuse caller-owned module scratch; clear every logical slot before evaluation.
pub(crate) fn evaluate_into(
    setup: &Setup,
    fields: &impl SemanticFields,
    m: &Module,
    inputs: &[(usize, Block)],
    evaluator: &mut wcss::GateEvaluator<'_>,
    values: &mut [Option<Block>],
) {
    assert_eq!(values.len(), m.gates.len());
    for value in values.iter_mut() {
        zeroize::Zeroize::zeroize(value);
    }
    let circuit = setup.circuit();
    let first = circuit.base() + m.gates.start;
    for i in m.gates.clone() {
        let g = circuit.gates()[i];
        let source = |wire: usize| {
            if wire >= first {
                values[wire - first]
            } else {
                inputs
                    .binary_search_by_key(&wire, |x| x.0)
                    .ok()
                    .map(|j| inputs[j].1)
            }
        };
        let (left, right) = (source(g.left), source(g.right));
        let chosen = match (g.op, left, right) {
            (Op::And, Some(a), Some(b)) => Some((3, [a, b])),
            (Op::Or, Some(a), _) => Some((1, [a, [0; 32]])),
            (Op::Or, None, Some(b)) => Some((2, [[0; 32], b])),
            _ => None,
        };
        if let Some((branches, tokens)) = chosen {
            values[i - m.gates.start] =
                evaluator.evaluate(i, branches, &tokens, |j| fields.correction(j));
        }
    }
}

/// A rejection needs authenticated entries, a reachable declared exit, and a
/// mismatch there. Unreachable exits and invalid entry labels are invalid proofs.
pub fn verify_fault(
    setup: &Setup,
    c: &Context,
    fields: &impl SemanticFields,
    module: usize,
    output: usize,
    inputs: &[(usize, Block)],
) -> bool {
    let Some(m) = witness(setup, module, output, inputs) else {
        return false;
    };
    if inputs
        .iter()
        .any(|(wire, token)| !equal(&wire_commitment(&c.id(), *wire, token), &fields.wire(*wire)))
    {
        return false;
    }
    let values = evaluate(setup, c, fields, m, inputs);
    values[output - setup.circuit().base() - m.gates.start].is_some_and(|token| {
        !equal(
            &wire_commitment(&c.id(), output, &token),
            &fields.wire(output),
        )
    })
}
