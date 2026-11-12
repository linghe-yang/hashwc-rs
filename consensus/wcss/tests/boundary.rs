use num_bigint::BigUint;
use types::Policy;
use wcss::{
    Circuit, Limits, Setup,
    boundary::{COLUMNS_PER_MODULE, Plan},
};

fn check(s: &Setup) {
    let c = s.circuit();
    let p = s.boundary().unwrap();
    assert_eq!(COLUMNS_PER_MODULE, 4);
    let mut owners = vec![usize::MAX; c.gates().len()];
    let mut next = 0;
    let mut next_correction = 0;
    for (id, m) in p.modules().iter().enumerate() {
        assert_eq!(m.gates.start, next);
        assert_eq!(m.corrections.start, next_correction);
        for i in m.gates.clone() {
            owners[i] = id;
            assert_eq!(c.gate_columns[i] / 4, m.column_group);
        }
        next = m.gates.end;
        next_correction = m.corrections.end;
        assert!(m.inputs.windows(2).all(|w| w[0] < w[1]));
        assert!(m.outputs.windows(2).all(|w| w[0] < w[1]));
    }
    assert_eq!(next, c.gates().len());
    assert_eq!(next_correction, s.correction_blocks());
    for (i, g) in c.gates().iter().enumerate() {
        let m = &p.modules()[owners[i]];
        for src in [g.left, g.right] {
            if src < c.base() || owners[src - c.base()] != owners[i] {
                assert!(m.inputs.binary_search(&src).is_ok());
                assert!(
                    p.index(src).is_some(),
                    "every cross-module CSE source is retained"
                );
                if src >= c.base() {
                    assert!(owners[src - c.base()] < owners[i]);
                    assert!(
                        p.modules()[owners[src - c.base()]]
                            .outputs
                            .binary_search(&src)
                            .is_ok()
                    );
                }
            }
        }
    }
    assert!(p.index(c.output()).is_some());
    assert!((0..c.base()).all(|w| p.index(w).is_some()));
    for (i, &wire) in p.wires().iter().enumerate() {
        assert_eq!(p.index(wire), Some(i));
    }
    assert_eq!(p.index(c.nodes()), None);
}

#[test]
fn manifest_covers_every_actual_cross_column_edge_after_cse_and_pruning() {
    for (n, shift) in [(1, 0), (6, 0), (8, 64), (9, 1024)] {
        let weights: Vec<BigUint> = (0..n)
            .map(|i| (BigUint::from(1u8) << shift) + BigUint::from(17u32 + 7 * i))
            .collect();
        let total: BigUint = weights.iter().sum();
        for threshold in [BigUint::from(1u8), &total / 3u8, total.clone()] {
            let s = Setup::new_clean(
                Policy::new(weights.clone(), threshold).unwrap(),
                Limits::default(),
            )
            .unwrap();
            check(&s);
            assert_eq!(
                Plan::new(s.circuit()).unwrap().id(),
                s.boundary().unwrap().id()
            );
        }
    }
}

#[test]
fn retained_provenance_is_not_reassigned_when_cse_reuses_old_gates() {
    use wcss::circuit::{Gate, Op};
    let c = Circuit {
        policy: Policy::new(vec![1u8.into(); 3], 2u8.into()).unwrap(),
        // The old OR at wire 5 is reused directly in columns 4 and 12.
        gates: vec![
            Gate {
                op: Op::Or,
                left: 2,
                right: 3,
            },
            Gate {
                op: Op::And,
                left: 4,
                right: 5,
            },
            Gate {
                op: Op::Or,
                left: 5,
                right: 6,
            },
        ],
        gate_columns: vec![0, 4, 12],
        output: 7,
    };
    let p = Plan::new(&c).unwrap();
    assert_eq!(p.modules().len(), 3);
    assert!(p.modules()[0].outputs.contains(&5));
    assert!(p.modules()[2].inputs.contains(&5));
    assert!(p.modules()[2].inputs.contains(&6));
    assert!(p.index(7).is_some());
    let mut malformed = c.clone();
    malformed.gate_columns[1] = 15;
    assert!(Plan::new(&malformed).is_err());
    malformed = c.clone();
    malformed.gates[0].right = 7;
    assert!(Plan::new(&malformed).is_err());
    malformed = c.clone();
    malformed.gate_columns.pop();
    assert!(Plan::new(&malformed).is_err());
    let mut different = c;
    different.gate_columns[2] = 8;
    assert_ne!(Plan::new(&different).unwrap().id(), p.id());
}
