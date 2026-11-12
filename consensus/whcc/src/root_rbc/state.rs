use super::{Message, Payload, Root};
use anyhow::{Result, ensure};
use num_bigint::BigUint;
use sdc_types::{InstanceId, SendAction, WeightedMembership};
use std::collections::BTreeMap;

/// One pre-registered dealer, one immutable vote per sender/phase.
pub struct State<T: Payload = Root> {
    party_weights: Vec<BigUint>,
    threshold: BigUint,
    quorum: BigUint,
    id: usize,
    pub instance: InstanceId,
    started: bool,
    echoed: Option<T>,
    ready: Option<T>,
    pub delivered: Option<T>,
    echoes: Vec<Option<T>>,
    readies: Vec<Option<T>>,
    weights: BTreeMap<T, [BigUint; 2]>,
    pub outgoing: Vec<SendAction<Message>>,
    pub events: Vec<T::Delivery>,
}
impl<T: Payload> State<T> {
    pub fn new(membership: WeightedMembership, id: usize, instance: InstanceId) -> Result<Self> {
        let n = membership.n();
        ensure!(
            id < n && instance.dealer.is_some_and(|d| d < n) && T::valid_slot(instance.slot),
            "invalid short-root instance/party"
        );
        Ok(Self {
            party_weights: membership
                .weights
                .iter()
                .map(|w| BigUint::from_bytes_be(&w.0.to_bytes_be()))
                .collect(),
            threshold: BigUint::from_bytes_be(&membership.threshold.to_bytes_be()),
            quorum: BigUint::from_bytes_be(&membership.quorum.to_bytes_be()),
            id,
            instance,
            started: false,
            echoed: None,
            ready: None,
            delivered: None,
            echoes: vec![None; n],
            readies: vec![None; n],
            weights: BTreeMap::new(),
            outgoing: vec![],
            events: vec![],
        })
    }
    pub fn broadcast(&mut self, root: T) -> Result<()> {
        ensure!(
            self.instance.dealer == Some(self.id) && !self.started,
            "only the dealer can broadcast, once"
        );
        self.started = true;
        self.send(root.kind(0));
        self.receive(
            self.id,
            Message {
                instance: self.instance,
                kind: root.kind(0),
            },
        );
        Ok(())
    }
    fn send(&mut self, kind: super::Kind) {
        for recipient in 0..self.party_weights.len() {
            if recipient != self.id {
                self.outgoing.push(SendAction {
                    recipient,
                    message: Message {
                        instance: self.instance,
                        kind: kind.clone(),
                    },
                });
            }
        }
    }
    fn vote(&mut self, sender: usize, phase: usize, root: T) -> bool {
        let slot = if phase == 0 {
            &mut self.echoes[sender]
        } else {
            &mut self.readies[sender]
        };
        if slot.is_some() {
            return false;
        }
        *slot = Some(root);
        self.weights.entry(root).or_default()[phase] += &self.party_weights[sender];
        true
    }
    fn cast(&mut self, phase: usize, root: T) {
        self.vote(self.id, phase, root); // Count self immediately, never via a network loopback.
        self.send(root.kind(phase + 1));
    }
    pub fn receive(&mut self, sender: usize, msg: Message) {
        let _profile = sdc_util::profile::span("rbc.bracha.root");
        if sender >= self.party_weights.len() || msg.instance != self.instance {
            return;
        }
        let Some((phase, root)) = T::extract(msg.kind) else {
            return;
        };
        if phase == 0 {
            if Some(sender) != self.instance.dealer || self.echoed.is_some() {
                return;
            }
            self.echoed = Some(root);
            self.cast(0, root);
        } else if !self.vote(sender, phase - 1, root) {
            return;
        }
        self.advance();
    }
    fn advance(&mut self) {
        if self.ready.is_none() {
            let candidate = self.weights.iter().find_map(|(root, w)| {
                (w[0] > self.quorum || w[1] >= self.threshold).then_some(*root)
            });
            if let Some(root) = candidate {
                self.ready = Some(root);
                self.cast(1, root);
            }
        }
        if self.delivered.is_none() {
            if let Some(root) = self
                .weights
                .iter()
                .find_map(|(root, w)| (w[1] > self.quorum).then_some(*root))
            {
                self.delivered = Some(root);
                self.events.push(root.event(self.instance));
            }
        }
        // Delivery does not disable a late INIT/ECHO or peer service.
    }
    #[cfg(test)]
    pub(super) fn vote_weights(&self, root: T) -> [BigUint; 2] {
        self.weights.get(&root).cloned().unwrap_or_default()
    }
    #[cfg(test)]
    pub(super) fn root_count(&self) -> usize {
        self.weights.len()
    }
}
