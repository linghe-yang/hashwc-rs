//! Physical-party orchestration of virtual-share HashRand.
use crate::{
    Parameters,
    bwavss::{Bundle, Outcome, Sharing, VerifiedBundle},
    msg::{Action, Behavior, Event, PRIVATE, RECONSTRUCT, SharePacket},
};
use anyhow::{Result, ensure};
use bincode::Options;
use config::Node;
use crypto::Block;
use network::Packet;
use num_bigint::BigUint;
use num_traits::{One, Zero};
use sdc_types::{Dyadic, InstanceId};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

#[cfg(test)]
mod tests;

struct RecoverySlot {
    private: Option<Arc<VerifiedBundle>>,
    pending: Option<Bundle>,
    checked_private: Option<Block>,
    checked_received: BTreeMap<usize, Block>,
    received: BTreeMap<usize, Arc<VerifiedBundle>>,
    received_tickets: usize,
    pending_received: BTreeMap<usize, Bundle>,
    sent: bool,
    value: Option<BigUint>,
}
struct Dealer {
    context: Block,
    roots: Option<Vec<Block>>,
    slots: Vec<RecoverySlot>,
    echoed: bool,
    private_slots: usize,
    complete: bool,
}
struct Batch {
    started: bool,
    dealers: Vec<Dealer>,
    gather: Option<Vec<usize>>,
    committee: Option<Vec<usize>>,
    coefficients: Option<Vec<Dyadic>>,
    release_input: bool,
    release_ready: bool,
    seed: Option<types::Coin>,
    open: Vec<bool>,
    output: Vec<Option<types::Coin>>,
}
pub struct State {
    pub id: usize,
    pub n: usize,
    pub params: Parameters,
    pub sharing: Sharing,
    pub behavior: Behavior,
    node: Node,
    batches: Vec<Batch>,
    started: bool,
    complete: bool,
    dirty_bundles: BTreeSet<(usize, usize, usize)>, // batch, dealer, slot
    dirty_recovery: BTreeSet<(usize, usize, usize)>, // batch, slot, dealer
    dirty_aggregate: BTreeSet<(usize, usize)>,
    outputs: usize,
    #[cfg(test)]
    checks: usize,
    #[cfg(test)]
    recovery_steps: usize,
    pub actions: Vec<Action>,
    pub events: Vec<Event>,
}
pub fn sample_committee(
    sharing: &Sharing,
    seed: types::Coin,
    context: Block,
    security: u32,
) -> Vec<usize> {
    // (2/3)^k <= 2^-security. Weighted Gather's honest core has weight > W/3.
    let mut k = 0usize;
    let mut three = BigUint::one();
    while three < (BigUint::one() << (k + security as usize)) {
        k += 1;
        three *= 3u8;
    }
    let bits = usize::BITS - (sharing.layout.total - 1).leading_zeros();
    let mask = (1u64 << bits) - 1;
    let mut counter = 0u64;
    let mut selected = BTreeSet::new();
    for _ in 0..k {
        let ticket = loop {
            let raw = crypto::hash(
                b"hashrand-vs/anytrust/v1",
                &[&context, &seed.to_be_bytes(), &counter.to_le_bytes()],
            );
            counter += 1;
            let candidate = (u64::from_le_bytes(raw[..8].try_into().unwrap()) & mask) as usize;
            if candidate < sharing.layout.total {
                break candidate;
            }
        };
        let owner = sharing.layout.ranges.partition_point(|r| r.end <= ticket);
        selected.insert(owner);
    }
    selected.into_iter().collect()
}
impl State {
    pub fn new(node: &Node, params: Parameters, behavior: Behavior) -> Result<Self> {
        params.validate(node)?;
        let sharing = Sharing::new(params.layout(node)?);
        let n = node.num_nodes;
        let batches = (0..params.batches)
            .map(|b| {
                let slots = params.slots(b, n);
                Batch {
                    started: false,
                    gather: None,
                    committee: None,
                    coefficients: None,
                    release_input: false,
                    release_ready: false,
                    seed: None,
                    open: vec![false; slots],
                    output: vec![None; slots],
                    dealers: (0..n)
                        .map(|d| Dealer {
                            context: params.context(node, b, d),
                            roots: None,
                            echoed: false,
                            private_slots: 0,
                            complete: false,
                            slots: (0..slots)
                                .map(|_| RecoverySlot {
                                    private: None,
                                    pending: None,
                                    checked_private: None,
                                    checked_received: BTreeMap::new(),
                                    received_tickets: 0,
                                    received: BTreeMap::new(),
                                    pending_received: BTreeMap::new(),
                                    sent: false,
                                    value: None,
                                })
                                .collect(),
                        })
                        .collect(),
                }
            })
            .collect();
        Ok(Self {
            id: node.id,
            n,
            params,
            sharing,
            behavior,
            node: node.clone(),
            batches,
            started: false,
            complete: false,
            dirty_bundles: BTreeSet::new(),
            dirty_recovery: BTreeSet::new(),
            dirty_aggregate: BTreeSet::new(),
            outputs: 0,
            #[cfg(test)]
            checks: 0,
            #[cfg(test)]
            recovery_steps: 0,
            actions: vec![],
            events: vec![],
        })
    }
    pub fn instance(&self, batch: usize, dealer: Option<usize>, slot: u64) -> InstanceId {
        InstanceId::new(self.params.epoch + batch as u64, dealer, slot)
    }
    /// All-honest local obligations, including zero-coefficient selected dealers.
    /// A completed application word alone does not imply these are fulfilled.
    pub fn service_progress(&self) -> sdc_util::observation::ServiceProgress {
        let mut pending = BTreeMap::from([
            ("sharing_completion", 0),
            ("root_vectors", 0),
            ("private_slots", 0),
            ("batch_gates", 0),
            ("unopened_slots", 0),
            ("slot_outputs", 0),
            ("selected_recovery_values", 0),
            ("selected_recovery_services", 0),
            (
                "dirty_work",
                self.dirty_bundles.len() + self.dirty_recovery.len() + self.dirty_aggregate.len(),
            ),
            ("application_actions", self.actions.len()),
            (
                "nonhonest_behavior",
                usize::from(!matches!(self.behavior, Behavior::Honest)),
            ),
        ]);
        for batch in &self.batches {
            pending.entry("batch_gates").and_modify(|n| {
                *n += usize::from(!batch.started)
                    + usize::from(batch.gather.is_none())
                    + usize::from(batch.committee.is_none())
                    + usize::from(batch.coefficients.is_none())
            });
            pending
                .entry("unopened_slots")
                .and_modify(|n| *n += batch.open.iter().filter(|&&x| !x).count());
            pending
                .entry("slot_outputs")
                .and_modify(|n| *n += batch.output.iter().filter(|x| x.is_none()).count());
            for (d, dealer) in batch.dealers.iter().enumerate() {
                pending
                    .entry("sharing_completion")
                    .and_modify(|n| *n += usize::from(!dealer.complete));
                pending
                    .entry("root_vectors")
                    .and_modify(|n| *n += usize::from(dealer.roots.is_none()));
                for slot in &dealer.slots {
                    pending
                        .entry("private_slots")
                        .and_modify(|n| *n += usize::from(slot.private.is_none()));
                    if batch
                        .committee
                        .as_ref()
                        .is_some_and(|c| c.binary_search(&d).is_ok())
                    {
                        pending
                            .entry("selected_recovery_values")
                            .and_modify(|n| *n += usize::from(slot.value.is_none()));
                        pending
                            .entry("selected_recovery_services")
                            .and_modify(|n| *n += usize::from(!slot.sent));
                    }
                }
            }
        }
        sdc_util::observation::ServiceProgress::new(self.complete, pending)
    }
    pub fn rbc_manifest(&self) -> Vec<wrbc::Request> {
        (0..self.params.batches)
            .flat_map(|b| {
                (0..self.n).map(move |d| wrbc::Request::Register {
                    instance: self.instance(b, Some(d), 0),
                    file_bytes: 32 * self.params.slots(b, self.n),
                    coding: wavid::CodingParams { block_bytes: 32 },
                })
            })
            .collect()
    }
    pub fn ra_manifest(&self) -> Vec<wra::Request> {
        let mut result = vec![];
        for b in 0..self.params.batches {
            for d in 0..self.n {
                result.push(wra::Request::Expect {
                    instance: self.instance(b, Some(d), 0),
                });
            }
            if self.params.seed_source(b, self.n).is_some() {
                result.push(wra::Request::Register {
                    instance: self.instance(b, None, 1),
                    header_id: crypto::hash(
                        b"hashrand-vs/seed-release/v1",
                        &[
                            &self.params.bound_node(&self.node).session_id,
                            &(b as u64).to_le_bytes(),
                        ],
                    ),
                });
            }
        }
        result
    }
    pub fn global(&self, b: usize) -> InstanceId {
        self.instance(b, None, 0)
    }
    pub fn start(&mut self) -> Result<()> {
        ensure!(!self.started, "HashRand already started");
        self.started = true;
        self.start_batch(0)?;
        self.advance()
    }
    fn start_batch(&mut self, b: usize) -> Result<()> {
        if self.batches[b].started {
            return Ok(());
        }
        let widths = (0..self.params.slots(b, self.n))
            .map(|s| self.params.contribution_width(s))
            .collect::<Vec<_>>();
        let generated = self.sharing.generate(
            self.batches[b].dealers[self.id].context,
            &widths,
            matches!(self.behavior, Behavior::InvalidPolynomial),
        )?;
        self.batches[b].started = true;
        self.actions.push(Action::Gather(wgather::Request::Start {
            instance: self.global(b),
        }));
        self.actions.push(Action::Rbc(wrbc::Request::Broadcast {
            instance: self.instance(b, Some(self.id), 0),
            data: generated.roots.concat(),
        }));
        for (recipient, bundles) in generated.packages.into_iter().enumerate() {
            for (slot, bundle) in bundles.into_iter().enumerate() {
                self.actions.push(Action::Private {
                    recipient,
                    packet: Packet {
                        epoch: self.params.epoch + b as u64,
                        dealer: self.id,
                        kind: PRIVATE,
                        payload: bincode::serialize(&SharePacket { slot, bundle })?,
                    },
                });
            }
        }
        Ok(())
    }
    fn batch_index(&self, epoch: u64) -> Option<usize> {
        let b = epoch.checked_sub(self.params.epoch)?;
        (b < self.params.batches as u64).then_some(b as usize)
    }
    pub fn rbc_event(&mut self, event: wrbc::Event) -> Result<()> {
        match event {
            wrbc::Event::Deliver { instance, data } => {
                return self.deliver_roots(instance, &data);
            }
            wrbc::Event::Rejected { reason, .. } => anyhow::bail!("WRBC: {reason}"),
            _ => {}
        }
        self.advance()
    }
    /// Called only after reliable delivery by coded RBC or fixed-root Bracha.
    pub fn deliver_roots(&mut self, instance: InstanceId, data: &[u8]) -> Result<()> {
        if let Some(b) = self.batch_index(instance.epoch)
            && instance.slot == 0
            && let Some(d) = instance.dealer.filter(|&d| d < self.n)
            && self.batches[b].dealers[d].roots.is_none()
            && data.len() == 32 * self.params.slots(b, self.n)
        {
            self.batches[b].dealers[d].roots = Some(data.as_chunks::<32>().0.to_vec());
            for s in 0..self.params.slots(b, self.n) {
                self.dirty_bundles.insert((b, d, s));
                self.schedule_recovery(b, s, d);
            }
            self.actions.push(Action::Ra(wra::Request::Register {
                instance,
                header_id: crypto::hash(
                    b"hashrand-vs/roots/v1",
                    &[&self.batches[b].dealers[d].context, &data],
                ),
            }));
        }
        self.advance()
    }
    pub fn ra_event(&mut self, event: wra::Event) -> Result<()> {
        match event {
            wra::Event::Output {
                instance,
                value: true,
            } => {
                if let Some(b) = self.batch_index(instance.epoch) {
                    if let Some(d) = instance.dealer.filter(|&d| d < self.n)
                        && instance.slot == 0
                        && self.batches[b].dealers[d].roots.is_some()
                        && !self.batches[b].dealers[d].complete
                    {
                        self.batches[b].dealers[d].complete = true;
                        self.events.push(Event::Shared {
                            batch: b,
                            dealer: d,
                        });
                        self.actions.push(Action::Gather(wgather::Request::Add {
                            instance: self.global(b),
                            dealer: d,
                        }));
                    } else if instance.dealer.is_none()
                        && instance.slot == 1
                        && let Some((source, slot)) = self.params.seed_source(b, self.n)
                        && !self.batches[b].release_ready
                    {
                        self.batches[b].release_ready = true;
                        self.open_slot(source, slot);
                        self.events.push(Event::SeedRelease {
                            target_batch: b,
                            source_batch: source,
                            source_slot: slot,
                        });
                    }
                }
            }
            wra::Event::Rejected { reason, .. } => anyhow::bail!("WRA: {reason}"),
            _ => {}
        }
        self.advance()
    }
    pub fn gather_event(&mut self, event: wgather::Event) -> Result<()> {
        match event {
            wgather::Event::DeliverSet { instance, dealers } => {
                if let Some(b) = self.batch_index(instance.epoch)
                    && instance == self.global(b)
                    && self.batches[b].gather.is_none()
                {
                    ensure!(
                        dealers
                            .iter()
                            .all(|&d| d < self.n && self.batches[b].dealers[d].complete),
                        "Gather returned uncompleted dealer"
                    );
                    self.events.push(Event::Gathered {
                        batch: b,
                        dealers: dealers.clone(),
                    });
                    self.batches[b].gather = Some(dealers);
                }
            }
            wgather::Event::Rejected { reason, .. } => anyhow::bail!("WGather: {reason}"),
            _ => {}
        }
        self.advance()
    }
    pub fn binaa_event(&mut self, event: wbinaa::Event) -> Result<()> {
        match event {
            wbinaa::Event::DeliverVector { instance, values } => {
                if let Some(b) = self.batch_index(instance.epoch)
                    && instance == self.global(b)
                    && self.batches[b].coefficients.is_none()
                {
                    ensure!(
                        values.len() == self.n && self.batches[b].committee.is_some(),
                        "unexpected AA vector"
                    );
                    let max = wbinaa::protocol::round_count(&self.params.precision(self.n))?;
                    let selected = self.batches[b].committee.as_ref().unwrap();
                    ensure!(
                        values.iter().enumerate().all(|(d, v)| v.exponent <= max
                            && BigUint::from_bytes_be(&v.numerator.0.to_bytes_be())
                                <= (BigUint::one() << v.exponent)
                            && (selected.contains(&d)
                                || v.numerator.0.to_bytes_be().iter().all(|&x| x == 0))),
                        "invalid AA output"
                    );
                    self.batches[b].coefficients = Some(values);
                    self.events.push(Event::Frozen { batch: b });
                    if b == 0 || self.application_done(b - 1) {
                        self.open_slot(b, 0);
                    }
                    // Reserved slots may have been released before this AA output.
                    for s in 0..self.params.slots(b, self.n) {
                        if self.batches[b].open[s] {
                            self.schedule_slot(b, s);
                        }
                    }
                }
            }
            wbinaa::Event::Rejected { reason, .. } => anyhow::bail!("WBinAA: {reason}"),
            _ => {}
        }
        self.advance()
    }
    pub fn packet(&mut self, sender: usize, packet: Packet) -> Result<()> {
        let Some(b) = self.batch_index(packet.epoch) else {
            return Ok(());
        };
        let d = packet.dealer;
        if sender >= self.n || d >= self.n || !matches!(packet.kind, PRIVATE | RECONSTRUCT) {
            return Ok(());
        }
        if packet.kind == PRIVATE && sender != d {
            return Ok(());
        }
        let Ok(decoded) = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(sdc_util::weighted::MAX_FRAME_BYTES as u64)
            .reject_trailing_bytes()
            .deserialize::<SharePacket>(&packet.payload)
        else {
            return Ok(());
        };
        if decoded.slot >= self.params.slots(b, self.n) {
            return Ok(());
        }
        let owner = if packet.kind == PRIVATE {
            self.id
        } else {
            sender
        };
        if decoded.bundle.shares.len() != self.sharing.layout.ranges[owner].len()
            || decoded.bundle.proof.len()
                > 2 * (self
                    .sharing
                    .layout
                    .total
                    .next_power_of_two()
                    .trailing_zeros() as usize
                    + 1)
        {
            return Ok(());
        }
        let index = decoded.slot;
        let slot = &mut self.batches[b].dealers[d].slots[index];
        if packet.kind == PRIVATE {
            if slot.private.is_some() || slot.pending.is_some() {
                return Ok(());
            }
            let digest = crypto::hash(b"hashrand-vs/packet-cache/v1", &[&packet.payload]);
            if slot.checked_private == Some(digest) {
                return Ok(());
            }
            slot.checked_private = Some(digest);
            slot.pending = Some(decoded.bundle);
        } else {
            if slot.value.is_some()
                || slot.received.contains_key(&sender)
                || slot.pending_received.contains_key(&sender)
            {
                return Ok(());
            }
            let digest = crypto::hash(b"hashrand-vs/packet-cache/v1", &[&packet.payload]);
            if slot.checked_received.get(&sender) == Some(&digest) {
                return Ok(());
            }
            slot.checked_received.insert(sender, digest);
            slot.pending_received.insert(sender, decoded.bundle);
        }
        self.dirty_bundles.insert((b, d, index));
        self.advance()
    }
    fn accept_bundles(&mut self) -> Result<()> {
        while let Some((b, d, s)) = self.dirty_bundles.pop_first() {
            let dealer = &mut self.batches[b].dealers[d];
            let Some(roots) = dealer.roots.as_ref() else {
                continue;
            };
            let slot = &mut dealer.slots[s];
            if let Some(bundle) = slot.pending.take() {
                #[cfg(test)]
                {
                    self.checks += 1;
                }
                if let Some(verified) =
                    self.sharing
                        .authenticate(dealer.context, s, roots[s], self.id, bundle)
                {
                    slot.private = Some(Arc::new(verified));
                    dealer.private_slots += 1;
                }
            }
            for (sender, bundle) in std::mem::take(&mut slot.pending_received) {
                if slot.value.is_some() || slot.received.contains_key(&sender) {
                    continue;
                }
                #[cfg(test)]
                {
                    self.checks += 1;
                }
                if let Some(verified) =
                    self.sharing
                        .authenticate(dealer.context, s, roots[s], sender, bundle)
                {
                    slot.received_tickets += verified.tickets();
                    slot.received.insert(sender, Arc::new(verified));
                }
            }
            if !dealer.echoed && dealer.private_slots == dealer.slots.len() {
                dealer.echoed = true;
                self.actions.push(Action::Ra(wra::Request::Input {
                    instance: InstanceId::new(self.params.epoch + b as u64, Some(d), 0),
                    value: true,
                }));
            }
            self.schedule_recovery(b, s, d);
        }
        Ok(())
    }
    fn application_done(&self, b: usize) -> bool {
        self.batches[b].output[self.params.batch_size - 1].is_some()
    }
    fn schedule_recovery(&mut self, b: usize, s: usize, d: usize) {
        let batch = &self.batches[b];
        if batch.open[s]
            && batch.coefficients.is_some()
            && batch
                .committee
                .as_ref()
                .is_some_and(|c| c.binary_search(&d).is_ok())
        {
            self.dirty_recovery.insert((b, s, d));
        }
    }
    fn schedule_slot(&mut self, b: usize, s: usize) {
        if self.batches[b].coefficients.is_none() {
            return;
        }
        for &d in self.batches[b].committee.as_ref().unwrap() {
            self.dirty_recovery.insert((b, s, d));
        }
        self.dirty_aggregate.insert((b, s));
    }
    fn open_slot(&mut self, b: usize, s: usize) {
        if !self.batches[b].open[s] {
            self.batches[b].open[s] = true;
            self.schedule_slot(b, s);
        }
    }
    fn prepare_committees(&mut self) -> Result<()> {
        for b in 0..self.params.batches {
            if self.batches[b].gather.is_none() || self.batches[b].committee.is_some() {
                continue;
            }
            let selected = if self.params.checkpoint(b, self.n) {
                Some((0..self.n).collect())
            } else if let Some(seed) = self.batches[b].seed {
                Some(sample_committee(
                    &self.sharing,
                    seed,
                    self.params.context(&self.node, b, 0),
                    self.params.sampling_bits,
                ))
            } else {
                if !self.batches[b].release_input {
                    self.batches[b].release_input = true;
                    self.actions.push(Action::Ra(wra::Request::Input {
                        instance: self.instance(b, None, 1),
                        value: true,
                    }));
                }
                None
            };
            if let Some(dealers) = selected {
                let mut inputs = vec![false; self.n];
                for &d in self.batches[b].gather.as_ref().unwrap() {
                    inputs[d] = true;
                }
                self.actions
                    .push(Action::BinAa(wbinaa::Request::StartSelected {
                        instance: self.global(b),
                        inputs,
                        coordinates: dealers.clone(),
                    }));
                self.events.push(Event::Committee {
                    batch: b,
                    sampled: !self.params.checkpoint(b, self.n),
                    dealers: dealers.clone(),
                });
                self.batches[b].committee = Some(dealers);
            }
        }
        Ok(())
    }
    fn recovery(&mut self) -> Result<()> {
        while let Some((b, s, d)) = self.dirty_recovery.pop_first() {
            #[cfg(test)]
            {
                self.recovery_steps += 1;
            }
            let dealer = &mut self.batches[b].dealers[d];
            let Some(roots) = dealer.roots.as_ref() else {
                continue;
            };
            let slot = &mut dealer.slots[s];
            if !slot.sent
                && !matches!(self.behavior, Behavior::WithholdRecovery)
                && let Some(bundle) = &slot.private
            {
                slot.sent = true;
                // Reuse our authenticated private receipt locally. The borrowed
                // tuple has exactly SharePacket's existing bincode wire encoding.
                let payload = bincode::serialize(&(s, bundle.bundle()))?;
                for recipient in 0..self.n {
                    if recipient != self.id {
                        self.actions.push(Action::Recovery {
                            recipient,
                            packet: Packet {
                                epoch: self.params.epoch + b as u64,
                                dealer: d,
                                kind: RECONSTRUCT,
                                payload: payload.clone(),
                            },
                        });
                    }
                }
                if slot.value.is_none()
                    && let std::collections::btree_map::Entry::Vacant(entry) =
                        slot.received.entry(self.id)
                {
                    slot.received_tickets += bundle.tickets();
                    entry.insert(Arc::clone(bundle));
                }
            }
            if slot.value.is_none()
                && slot.received_tickets >= self.sharing.layout.threshold
                && let Some(outcome) = self.sharing.recover_verified(
                    dealer.context,
                    s,
                    roots[s],
                    slot.received.values().map(Arc::as_ref),
                    self.params.contribution_width(s),
                )
            {
                let rejected = matches!(outcome, Outcome::Rejected);
                slot.value = Some(match outcome {
                    Outcome::Value(v) => v,
                    Outcome::Rejected => BigUint::zero(),
                });
                slot.received.clear();
                slot.pending_received.clear();
                slot.received_tickets = 0;
                self.dirty_aggregate.insert((b, s));
                self.events.push(Event::Reconstructed {
                    batch: b,
                    dealer: d,
                    slot: s,
                    rejected,
                });
            }
        }
        while let Some((b, s)) = self.dirty_aggregate.pop_first() {
            if self.batches[b].output[s].is_some() {
                continue;
            }
            let Some(value) = whcc::aggregate::aggregate_borrowed(
                self.batches[b].coefficients.as_ref().unwrap(),
                self.batches[b]
                    .dealers
                    .iter()
                    .map(|d| d.slots[s].value.as_ref()),
                self.params.rounding_bits,
                self.params.output_width(s),
            )?
            else {
                continue;
            };
            self.batches[b].output[s] = Some(value);
            self.outputs += 1;
            if s < self.params.batch_size {
                self.events.push(Event::Beacon {
                    batch: b,
                    index: s,
                    value,
                });
                if s + 1 < self.params.batch_size {
                    self.open_slot(b, s + 1);
                } else if b + 1 < self.params.batches && self.batches[b + 1].coefficients.is_some()
                {
                    self.open_slot(b + 1, 0);
                }
            } else {
                let target = b + s - self.params.batch_size + 1;
                ensure!(
                    target < self.params.batches && self.batches[target].release_ready,
                    "reserved randomness opened before target Gather gate"
                );
                self.batches[target].seed = Some(value);
                self.events.push(Event::SeedOpened {
                    target_batch: target,
                    value,
                });
            }
        }
        Ok(())
    }
    pub fn advance(&mut self) -> Result<()> {
        self.accept_bundles()?;
        if self.started {
            for b in 1..self.params.batches {
                if self.batches[b - 1].coefficients.is_some() && !self.batches[b].started {
                    self.start_batch(b)?;
                }
            }
        }
        loop {
            let before = self.outputs;
            self.prepare_committees()?;
            self.recovery()?;
            self.prepare_committees()?;
            let after = self.outputs;
            if before == after {
                break;
            }
        }
        if !self.complete
            && self.outputs == self.batches.iter().map(|b| b.output.len()).sum::<usize>()
        {
            self.complete = true;
            self.events.push(Event::Complete);
        }
        Ok(())
    }
}
