use crate::{Entry, Event, Precision, ProtMsg};
use anyhow::{ensure, Result};
use num_bigint::{BigInt, BigUint};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use types::{Dyadic, InstanceId, SendAction, Weight, WeightedMembership};
pub const MAX_ROUNDS: u32 = 4096;
pub fn round_count(precision: &Precision) -> Result<u32> {
    ensure!(
        precision.numerator.0 > BigUint::from(0u8)
            && precision.numerator.0 <= precision.denominator.0,
        "precision must be an exact fraction in (0,1]"
    );
    let mut r = 0;
    while (&precision.numerator.0 << r as usize) < precision.denominator.0 {
        r += 1;
        ensure!(r <= MAX_ROUNDS, "BinAA round resource limit");
    }
    Ok(r)
}
#[derive(Default)]
pub(crate) struct SenderRound {
    pub slots: [Option<u8>; 3],
    pub baseline: Option<BigInt>,
    pub used: [bool; 3],
}
#[derive(Default)]
pub(crate) struct Vote {
    pub senders: BTreeSet<usize>,
    pub weight: BigUint,
}
#[derive(Default)]
pub(crate) struct RoundState {
    pub senders: HashMap<usize, SenderRound>,
    pub w1: BTreeMap<BigInt, Vote>,
    pub w2: BTreeMap<BigInt, Vote>,
    pub initial: Option<BigInt>,
    pub sent1: BTreeSet<BigInt>,
    pub sent2: Option<BigInt>,
    pub result: Option<BigInt>,
}
/// Each coordinate progresses independently. Old rounds still relay after vector output.
pub struct State {
    pub membership: WeightedMembership,
    pub id: usize,
    pub instance: InstanceId,
    pub rounds: u32,
    pub(crate) coordinates: BTreeSet<usize>,
    pub output: Option<Vec<Dyadic>>,
    pub outgoing: Vec<SendAction<ProtMsg>>,
    pub events: Vec<Event>,
    pub(crate) inputs: Option<Vec<bool>>,
    pub(crate) states: HashMap<(usize, u32), RoundState>,
    pub(crate) finished: BTreeMap<usize, BigInt>,
    pub(crate) work: VecDeque<(usize, u32)>,
    pub(crate) pending: BTreeMap<u32, Vec<Entry>>,
    pub(crate) batch_entries: usize,
}
impl State {
    pub fn new(
        membership: WeightedMembership,
        id: usize,
        instance: InstanceId,
        precision: Precision,
    ) -> Result<Self> {
        ensure!(
            membership.n() <= 4096 && id < membership.n() && instance.dealer.is_none(),
            "BinAA requires a global instance and at most 4096 participants"
        );
        let rounds = round_count(&precision)?;
        let coordinates = (0..membership.n()).collect();
        Ok(Self {
            coordinates,
            membership,
            id,
            instance,
            rounds,
            output: None,
            outgoing: vec![],
            events: vec![],
            inputs: None,
            states: HashMap::new(),
            finished: BTreeMap::new(),
            work: VecDeque::new(),
            pending: BTreeMap::new(),
            batch_entries: 256,
        })
    }
    pub fn start(&mut self, inputs: Vec<bool>) -> Result<()> {
        self.start_selected(inputs, (0..self.membership.n()).collect())
    }
    pub fn start_selected(&mut self, inputs: Vec<bool>, coordinates: Vec<usize>) -> Result<()> {
        let selected: BTreeSet<_> = coordinates.iter().copied().collect();
        ensure!(
            !selected.is_empty()
                && selected.len() == coordinates.len()
                && selected.iter().all(|&c| c < self.membership.n()),
            "nonempty distinct in-range coordinates required"
        );
        ensure!(
            self.inputs.is_none() && inputs.len() == self.membership.n(),
            "one input vector with one bit per dealer required"
        );
        self.coordinates = selected;
        self.states.retain(|(c, _), _| self.coordinates.contains(c));
        self.work.retain(|(c, _)| self.coordinates.contains(c));
        self.inputs = Some(inputs.clone());
        if self.rounds == 0 {
            let values: Vec<_> = inputs
                .iter()
                .enumerate()
                .map(|(c, b)| Dyadic {
                    numerator: Weight::from((*b && self.coordinates.contains(&c)) as u64),
                    exponent: 0,
                })
                .collect();
            self.output = Some(values.clone());
            self.events.push(Event::DeliverVector {
                instance: self.instance,
                values,
            });
            return Ok(());
        }
        for (c, b) in inputs.into_iter().enumerate() {
            if self.coordinates.contains(&c) {
                self.enter(c, 1, BigInt::from(b as u8));
            }
        }
        self.advance();
        Ok(())
    }
    pub fn receive(&mut self, sender: usize, msg: ProtMsg) {
        if sender >= self.membership.n()
            || msg.instance != self.instance
            || msg.round == 0
            || msg.round > self.rounds
            || msg.entries.is_empty()
            || msg.entries.len() > 3 * self.membership.n()
        {
            return;
        }
        let mut seen = BTreeSet::new();
        for entry in &msg.entries {
            let role = if entry.code < 5 {
                0
            } else if entry.code < 8 {
                1
            } else {
                2
            };
            if entry.coordinate as usize >= self.membership.n()
                || entry.code > 10
                || (msg.round == 1 && role == 0 && entry.code != 2 && entry.code != 3)
                || !seen.insert((entry.coordinate, role))
            {
                return;
            }
        }
        let mut touched = BTreeSet::new();
        for entry in msg.entries {
            let c = entry.coordinate as usize;
            if self.inputs.is_some() && !self.coordinates.contains(&c) {
                continue;
            }
            let role = if entry.code < 5 {
                0
            } else if entry.code < 8 {
                1
            } else {
                2
            };
            let source = self
                .states
                .entry((c, msg.round))
                .or_default()
                .senders
                .entry(sender)
                .or_default();
            if source.slots[role].is_none() {
                source.slots[role] = Some(entry.code);
                touched.insert(c);
            }
        }
        for c in touched {
            self.decode_chain(c, msg.round, sender);
        }
        self.advance();
    }
    pub(crate) fn decode_chain(&mut self, c: usize, mut r: u32, sender: usize) {
        while r <= self.rounds {
            let Some(source) = self
                .states
                .get(&(c, r))
                .and_then(|s| s.senders.get(&sender))
            else {
                return;
            };
            let Some(initial_code) = source.slots[0] else {
                return;
            };
            let newly = source.baseline.is_none();
            if newly {
                let previous = if r == 1 {
                    BigInt::from(0)
                } else {
                    let Some(v) = self
                        .states
                        .get(&(c, r - 1))
                        .and_then(|s| s.senders.get(&sender))
                        .and_then(|s| s.baseline.clone())
                    else {
                        return;
                    };
                    v
                };
                let baseline = previous * 2 + BigInt::from(initial_code) - 2;
                if baseline < BigInt::from(0) || baseline > (BigInt::from(1) << ((r - 1) as usize))
                {
                    return;
                }
                self.states
                    .get_mut(&(c, r))
                    .unwrap()
                    .senders
                    .get_mut(&sender)
                    .unwrap()
                    .baseline = Some(baseline);
            }
            let state = self.states.get_mut(&(c, r)).unwrap();
            let source = state.senders.get_mut(&sender).unwrap();
            let baseline = source.baseline.as_ref().unwrap().clone();
            for role in 0..3 {
                if source.used[role] {
                    continue;
                }
                let Some(code) = source.slots[role] else {
                    continue;
                };
                source.used[role] = true;
                let delta = if role == 0 {
                    0
                } else {
                    code as i32 - if role == 1 { 6 } else { 9 }
                };
                let value = &baseline + delta;
                if value < BigInt::from(0) || value > (BigInt::from(1) << ((r - 1) as usize)) {
                    continue;
                }
                let votes = if role == 2 {
                    &mut state.w2
                } else {
                    &mut state.w1
                };
                let vote = votes.entry(value).or_default();
                if vote.senders.insert(sender) {
                    vote.weight += &self.membership.weights[sender].0;
                    self.work.push_back((c, r));
                }
            }
            if !newly {
                return;
            }
            r += 1;
        }
    }
}
