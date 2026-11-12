use crate::{Entry, Event, ProtMsg, State};
use num_bigint::BigInt;
use num_traits::ToPrimitive;
use types::{Dyadic, SendAction, Weight};
impl State {
    fn record(&mut self, c: usize, r: u32, code: BigInt, lower: u8, upper: u8) {
        if let Some(code) = code.to_u8().filter(|code| *code >= lower && *code <= upper) {
            self.pending.entry(r).or_default().push(Entry {
                coordinate: c as u32,
                code,
            });
        } else {
            log::error!("BinAA adjacent-grid invariant failed; no value is rounded");
        }
    }
    pub(crate) fn enter(&mut self, c: usize, r: u32, numerator: BigInt) {
        let previous = if r == 1 {
            BigInt::from(0)
        } else {
            self.states[&(c, r - 1)].initial.as_ref().unwrap().clone()
        };
        let state = self.states.entry((c, r)).or_default();
        state.initial = Some(numerator.clone());
        state.sent1.insert(numerator.clone());
        self.record(c, r, numerator - previous * 2 + 2, 0, 4);
        self.work.push_back((c, r));
    }
    pub(crate) fn advance(&mut self) {
        while let Some((c, r)) = self.work.pop_front() {
            let Some(initial) = self.states.get(&(c, r)).and_then(|s| s.initial.clone()) else {
                continue;
            };
            let relays: Vec<_> = self.states[&(c, r)]
                .w1
                .iter()
                .filter(|(value, vote)| {
                    vote.weight >= self.membership.threshold
                        && !self.states[&(c, r)].sent1.contains(*value)
                })
                .map(|(v, _)| v.clone())
                .collect();
            for value in relays {
                let state = self.states.get_mut(&(c, r)).unwrap();
                if state.sent1.len() >= 2 {
                    continue;
                }
                state.sent1.insert(value.clone());
                self.record(c, r, value - &initial + 6, 5, 7);
            }
            // A certificate needs W-(T-1) weight: the maximum corruption is T-1.
            let certified: Vec<_> = self.states[&(c, r)]
                .w1
                .iter()
                .filter(|(_, v)| v.weight > self.membership.quorum)
                .map(|(v, _)| v.clone())
                .collect();
            if !certified.is_empty() && self.states[&(c, r)].sent2.is_none() {
                let value = certified[0].clone();
                self.states.get_mut(&(c, r)).unwrap().sent2 = Some(value.clone());
                self.record(c, r, value - &initial + 9, 8, 10);
            }
            if self.states[&(c, r)].result.is_some() {
                continue;
            }
            let result = if certified.len() >= 2 {
                Some(&certified[0] + &certified[1])
            } else {
                self.states[&(c, r)]
                    .w2
                    .iter()
                    .find(|(_, v)| v.weight > self.membership.quorum)
                    .map(|(v, _)| v * 2)
            };
            if let Some(result) = result {
                self.states.get_mut(&(c, r)).unwrap().result = Some(result.clone());
                if r < self.rounds {
                    self.enter(c, r + 1, result);
                } else {
                    self.finished.insert(c, result);
                    if self.output.is_none() && self.finished.len() == self.coordinates.len() {
                        let values: Vec<_> = (0..self.membership.n())
                            .map(|c| Dyadic {
                                numerator: Weight(
                                    self.finished
                                        .get(&c)
                                        .cloned()
                                        .unwrap_or_default()
                                        .to_biguint()
                                        .expect("nonnegative BinAA numerator"),
                                ),
                                exponent: self.rounds,
                            })
                            .collect();
                        self.output = Some(values.clone());
                        self.events.push(Event::DeliverVector {
                            instance: self.instance,
                            values,
                        });
                    }
                }
            }
        }
        // Bundle ready coordinates without imposing a cross-coordinate round barrier.
        for (round, entries) in std::mem::take(&mut self.pending) {
            for entries in entries.chunks(self.batch_entries) {
                let msg = ProtMsg {
                    instance: self.instance,
                    round,
                    entries: entries.to_vec(),
                };
                for recipient in 0..self.membership.n() {
                    self.outgoing.push(SendAction {
                        recipient,
                        message: msg.clone(),
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod compact_batch_tests {
    use super::*;
    use crate::Precision;
    use types::{InstanceId, WeightedMembership};

    #[test]
    fn compact_ready_batch_fits_all_273_slots_and_never_waits_to_fill() {
        let membership =
            WeightedMembership::new(vec![Weight::from(3); 91], Weight::from(91)).unwrap();
        let mut state = State::new(
            membership,
            0,
            InstanceId::new(0, None, 0),
            Precision::bits(2),
        )
        .unwrap();
        let entries: Vec<_> = (0..91u32)
            .flat_map(|coordinate| {
                [
                    Entry {
                        coordinate,
                        code: 2,
                    },
                    Entry {
                        coordinate,
                        code: 5,
                    },
                    Entry {
                        coordinate,
                        code: 9,
                    },
                ]
            })
            .collect();
        state.pending.insert(2, entries.clone());
        state.advance();
        assert_eq!(state.outgoing.len(), 182); // legacy 256 + 17
        state.outgoing.clear();
        state.batch_entries = 273;
        state.pending.insert(2, entries);
        state.advance();
        assert_eq!(state.outgoing.len(), 91);
        assert!(
            state
                .outgoing
                .iter()
                .all(|a| a.message.entries.len() == 273)
        );
        state.outgoing.clear();
        state.pending.insert(
            2,
            vec![Entry {
                coordinate: 90,
                code: 9,
            }],
        );
        state.advance();
        assert_eq!(state.outgoing.len(), 91); // no waiting for another coordinate
        assert!(state.outgoing.iter().all(|a| a.message.entries.len() == 1));
    }
}

#[cfg(test)]
mod integer_quorum_regressions {
    use super::*;
    use crate::Precision;
    use types::{InstanceId, WeightedMembership};
    #[test]
    fn second_stage_also_needs_three_votes_in_the_four_party_boundary_case() {
        let m = WeightedMembership::new(vec![Weight::from(1); 4], Weight::from(2)).unwrap();
        let mut s = State::new(m, 0, InstanceId::new(0, None, 0), Precision::bits(1)).unwrap();
        s.start(vec![false; 4]).unwrap();
        s.states.get_mut(&(0, 1)).unwrap().w2.insert(
            BigInt::from(0),
            crate::protocol::state::Vote {
                weight: 2u8.into(),
                ..Default::default()
            },
        );
        s.work.push_back((0, 1));
        s.advance();
        assert!(s.states[&(0, 1)].result.is_none());
        s.states
            .get_mut(&(0, 1))
            .unwrap()
            .w2
            .get_mut(&BigInt::from(0))
            .unwrap()
            .weight = 3u8.into();
        s.work.push_back((0, 1));
        s.advance();
        assert!(s.states[&(0, 1)].result.is_some());
    }

    #[test]
    fn two_votes_are_not_a_certificate_when_four_parties_allow_one_fault() {
        let m = WeightedMembership::new(vec![Weight::from(1); 4], Weight::from(2)).unwrap();
        let mut s = State::new(m, 0, InstanceId::new(0, None, 0), Precision::bits(1)).unwrap();
        s.start(vec![false; 4]).unwrap();
        let state = s.states.get_mut(&(0, 1)).unwrap();
        state.w1.insert(
            BigInt::from(0),
            crate::protocol::state::Vote {
                weight: 2u8.into(),
                ..Default::default()
            },
        );
        s.work.push_back((0, 1));
        s.advance();
        assert!(s.states[&(0, 1)].sent2.is_none());
        assert!(s.output.is_none());
        s.states
            .get_mut(&(0, 1))
            .unwrap()
            .w1
            .get_mut(&BigInt::from(0))
            .unwrap()
            .weight = 3u8.into();
        s.work.push_back((0, 1));
        s.advance();
        assert!(s.states[&(0, 1)].sent2.is_some());
    }
}
