use super::*;
use hashwc_types::{Instance, Policy};
use std::collections::VecDeque;
#[test]
fn malicious_dealer_with_valid_ax_binding_but_tampered_absent_input_produces_common_bottom() {
    let policy = Policy::from_strings(&["1"; 7].map(str::to_owned), "2").unwrap();
    let setup = Arc::new(Setup::new(policy, crate::Limits::default()).unwrap());
    let context = Context::new(
        &setup,
        Instance {
            session: [8; 32],
            epoch: 1,
            dealer: 0,
        },
        vec![],
    )
    .unwrap();
    let opening = Opening {
        message: [7; 32],
        randomness: [9; 32],
    };
    let (mut public, shares) = ax::generate(&setup, &context, &opening).unwrap();
    public.base.inputs[6][0] ^= 1;
    let material = hashwc_crypto::expand(
        b"AX/derive",
        &[&context.id(), &opening.message, &opening.randomness],
        128,
    );
    let root = hashwc_crypto::hash(
        b"coins/token",
        &[
            &material[96..],
            &context.id(),
            &(setup.circuit().output() as u64).to_le_bytes(),
        ],
    );
    public.base.tag = [0; 32];
    public.base.tag = hashwc_crypto::hash(
        b"transcript",
        &[&context.id(), &root, &public.base.encode()],
    );
    let mut nodes: Vec<_> = (0..7)
        .map(|i| State::new(setup.clone(), context.clone(), i).unwrap())
        .collect();
    nodes[0].start_generated(public, shares).unwrap();
    for node in &mut nodes {
        node.begin_reconstruction().unwrap();
    }
    let mut queue = VecDeque::new();
    let mut bottom = [false; 7];
    let mut shared = [false; 7];
    let mut steps = 0;
    loop {
        for (i, node) in nodes.iter_mut().enumerate() {
            for a in node.drain_actions() {
                queue.push_back((i, a));
            }
            for e in node.drain_events() {
                match e {
                    Event::Shared => shared[i] = true,
                    Event::Bottom => {
                        assert!(!bottom[i]);
                        bottom[i] = true;
                    }
                    other => panic!("unexpected {other:?}"),
                }
            }
        }
        match queue.pop_front() {
            Some((sender, a)) => nodes[a.recipient].receive(sender, a.message).unwrap(),
            None => break,
        }
        steps += 1;
        assert!(steps < 100_000);
    }
    assert!(shared.into_iter().all(|x| x));
    assert!(bottom.into_iter().all(|x| x));
}
