use std::sync::Arc;
use types::{Instance, Policy};
use wiawvss::{Context, Event, Limits, Message, Opening, Setup, State};

struct Network {
    nodes: Vec<State>,
    queue: Vec<(usize, usize, Message)>,
    silent: Vec<usize>,
    seed: u64,
    outputs: Vec<Option<Opening>>,
    shared: Vec<bool>,
    releases: usize,
    deliveries: usize,
}
impl Network {
    fn new(weights: &[&str], threshold: &str, silent: Vec<usize>, seed: u64) -> Self {
        let policy = Policy::from_strings(
            &weights.iter().map(|x| x.to_string()).collect::<Vec<_>>(),
            threshold,
        )
        .unwrap();
        let setup = Arc::new(Setup::new(policy, Limits::default()).unwrap());
        let context = Context::new(
            &setup,
            Instance {
                session: [3; 32],
                epoch: 0,
                dealer: 0,
            },
            vec![],
        )
        .unwrap();
        let nodes = (0..weights.len())
            .map(|id| State::new(setup.clone(), context.clone(), id).unwrap())
            .collect();
        Self {
            nodes,
            queue: vec![],
            silent,
            seed,
            outputs: vec![None; weights.len()],
            shared: vec![false; weights.len()],
            releases: 0,
            deliveries: 0,
        }
    }
    fn collect(&mut self) {
        for (sender, node) in self.nodes.iter_mut().enumerate() {
            for a in node.drain_actions() {
                if matches!(a.message, Message::Open(_)) {
                    self.releases += 1;
                }
                if !self.silent.contains(&sender) && !self.silent.contains(&a.recipient) {
                    self.queue.push((sender, a.recipient, a.message));
                }
            }
            for e in node.drain_events() {
                match e {
                    Event::Shared => {
                        assert!(!self.shared[sender]);
                        self.shared[sender] = true;
                    }
                    Event::Reconstructed(r) => {
                        assert!(self.outputs[sender].is_none());
                        self.outputs[sender] = Some(r.opening);
                    }
                    other => panic!("unexpected event {other:?}"),
                }
            }
        }
    }
    fn settle(&mut self) {
        self.collect();
        while !self.queue.is_empty() {
            self.seed ^= self.seed << 13;
            self.seed ^= self.seed >> 7;
            self.seed ^= self.seed << 17;
            let index = self.seed as usize % self.queue.len();
            let (sender, to, msg) = self.queue.swap_remove(index);
            // Duplicate selected packets without creating an unbounded resend loop.
            if self.seed.is_multiple_of(5) {
                self.nodes[to].receive(sender, msg.clone()).unwrap();
            }
            self.nodes[to].receive(sender, msg).unwrap();
            self.deliveries += 1;
            assert!(self.deliveries < 1_000_000, "protocol failed to quiesce");
            self.collect();
        }
    }
    fn start(&mut self) -> Opening {
        let opening = Opening {
            message: [19; 32],
            randomness: [61; 32],
        };
        self.nodes[0].start_with_opening(&opening).unwrap();
        opening
    }
    fn honest(&self) -> Vec<usize> {
        (0..self.nodes.len())
            .filter(|id| !self.silent.contains(id))
            .collect()
    }
}
#[test]
fn asynchronous_composition_with_silent_fault_and_duplicate_reordered_packets() {
    for seed in 1..=8 {
        // B=1 < T=2, W=7: exactly the strict weighted paper convention.
        let mut n = Network::new(&["1"; 7], "2", vec![6], seed);
        let opening = n.start();
        n.settle();
        for id in n.honest() {
            assert!(n.shared[id]);
            assert!(n.outputs[id].is_none());
        }
        assert_eq!(n.releases, 0, "sharing must not reveal private tokens");
        for id in n.honest() {
            n.nodes[id].begin_reconstruction().unwrap();
        }
        n.settle();
        for id in n.honest() {
            assert_eq!(n.outputs[id].as_ref().unwrap(), &opening);
        }
    }
}
#[test]
fn skewed_huge_weights_and_early_local_reconstruction_request() {
    let mut n = Network::new(
        &[
            "300000000000000000000000000000000000000",
            "400000000000000000000000000000000000000",
            "500000000000000000000000000000000000000",
            "600000000000000000000000000000000000000",
        ],
        "600000000000000000000000000000000000000",
        vec![2],
        17,
    );
    for id in n.honest() {
        n.nodes[id].begin_reconstruction().unwrap();
    }
    let opening = n.start();
    n.settle();
    for id in n.honest() {
        assert!(n.shared[id]);
        assert_eq!(n.outputs[id].as_ref().unwrap(), &opening);
    }
}
#[test]
fn late_local_token_is_served_after_completion_and_after_output() {
    let mut n = Network::new(&["1"; 7], "2", vec![], 23);
    let opening = n.start();
    n.collect();
    // Delay the dealer's private token to party 5. The other six can complete.
    let pos = n
        .queue
        .iter()
        .position(|(_, to, msg)| *to == 5 && matches!(msg, Message::Private(_)))
        .unwrap();
    let late = n.queue.swap_remove(pos);
    n.settle();
    assert!(n.shared.iter().all(|v| *v));
    assert_eq!(n.releases, 0);
    for id in 0..7 {
        n.nodes[id].begin_reconstruction().unwrap();
    }
    n.settle();
    assert!(n.outputs.iter().all(|o| o.as_ref() == Some(&opening)));
    let before = n.releases;
    n.nodes[late.1].receive(late.0, late.2).unwrap();
    n.settle();
    assert_eq!(n.releases, before + 7);
}
#[test]
fn forged_owner_and_invalid_first_opening_do_not_poison_honest_slots() {
    let mut n = Network::new(&["1"; 7], "2", vec![], 31);
    let opening = n.start();
    n.settle();
    for id in 0..7 {
        n.nodes[id].begin_reconstruction().unwrap();
    }
    n.collect();
    let (sender, to, msg) = n
        .queue
        .iter()
        .find(|(_, _, m)| matches!(m, Message::Open(_)))
        .unwrap()
        .clone();
    n.nodes[to].receive((sender + 1) % 7, msg.clone()).unwrap();
    if let Message::Open(mut s) = msg {
        s.token[0] ^= 1;
        n.nodes[to].receive(sender, Message::Open(s)).unwrap();
    }
    n.settle();
    assert!(n.outputs.iter().all(|o| o.as_ref() == Some(&opening)));
}
#[test]
fn no_completion_without_authentic_receipts_and_no_timeout_bottom() {
    let mut n = Network::new(&["1"; 7], "2", vec![], 37);
    n.start();
    n.collect();
    n.queue
        .retain(|(_, _, m)| !matches!(m, Message::Private(_)));
    n.settle();
    assert!(!n.shared.iter().any(|x| *x));
    for id in 0..7 {
        n.nodes[id].begin_reconstruction().unwrap();
    }
    n.settle();
    assert_eq!(n.releases, 0);
    assert!(n.outputs.iter().all(Option::is_none));
}
#[test]
fn duplicate_start_and_invalid_async_threshold_are_rejected() {
    let mut n = Network::new(&["1"; 7], "2", vec![], 41);
    n.start();
    assert!(n.nodes[0].start([0; 32]).is_err());
    assert!(n.nodes[1].start([0; 32]).is_err());
    let p = Policy::from_strings(&["1"; 4].map(str::to_owned), "2").unwrap();
    let s = Arc::new(Setup::new(p, Limits::default()).unwrap());
    let c = Context::new(
        &s,
        Instance {
            session: [0; 32],
            epoch: 0,
            dealer: 0,
        },
        vec![],
    )
    .unwrap();
    assert!(State::new(s, c, 0).is_err());
}

#[test]
fn late_release_barrier_and_repeated_calls_preserve_single_output() {
    let mut n = Network::new(&["1"; 7], "2", vec![], 47);
    let opening = n.start();
    n.settle();
    for id in 0..6 {
        n.nodes[id].begin_reconstruction().unwrap();
    }
    n.settle();
    assert!(n.outputs[..6].iter().all(|o| o.as_ref() == Some(&opening)));
    assert!(n.outputs[6].is_none());
    let before = n.releases;
    n.nodes[6].begin_reconstruction().unwrap();
    n.settle();
    assert_eq!(n.outputs[6].as_ref(), Some(&opening));
    assert_eq!(n.releases, before + 7);
    for node in &mut n.nodes {
        node.begin_reconstruction().unwrap();
    }
    n.settle();
    assert_eq!(n.releases, before + 7);
}
