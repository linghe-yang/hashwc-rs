//! HashRand/Freitas control framework with full-record CSS+AX sharing.
use crate::{
    Parameters,
    msg::{Action, Behavior, Event, PRIVATE, RECONSTRUCT},
};
use anyhow::{Result, ensure};
use network::Packet;
use num_bigint::BigUint;
use num_traits::Zero;
use sdc_types::{Dyadic, InstanceId};
use std::collections::{BTreeMap, BTreeSet};
use wcss::Setup;
use wiawvss::{
    Context as SharingContext, PrivateShare,
    compact::{self, Public},
};
use zeroize::Zeroizing;

struct Dealer {
    context: SharingContext,
    public: Option<wavid::ValidatedFile>,
    invalid_public: bool,
    pending_private: Option<PrivateShare>,
    receipt: Option<PrivateShare>,
    pending_tokens: BTreeMap<usize, PrivateShare>,
    checked_tokens: Zeroizing<Vec<Option<crypto::Block>>>,
    checked_private: Zeroizing<Option<crypto::Block>>,
    verified_weight: BigUint,
    #[cfg(test)]
    token_checks: usize,
    #[cfg(test)]
    recovery_attempts: usize,
    tokens: Vec<Option<PrivateShare>>,
    echoed: bool,
    complete: bool,
    served: bool,
    value: Option<BigUint>,
    dirty: bool,
}
pub struct State {
    pub(crate) id: usize,
    n: usize,
    setup: Setup,
    params: Parameters,
    pub block_selection: wiawvss::blocksize::Selection,
    behavior: Behavior,
    dealers: Vec<Dealer>,
    gather: Option<Vec<usize>>,
    coefficients: Option<Vec<Dyadic>>,
    started: bool,
    coin: Option<types::Coin>,
    dirty_dealers: BTreeSet<usize>,
    recovery_work: sdc_util::weighted_work::RecoveryQueue,
    cooperative_recovery: bool,
    remaining: usize,
    range: BigUint,
    #[cfg(test)]
    dealer_steps: usize,
    pub(crate) actions: Vec<Action>,
    pub(crate) events: Vec<Event>,
}
impl State {
    pub fn parameters(&self) -> &Parameters {
        &self.params
    }
    pub fn new(node: &config::Node, params: Parameters, behavior: Behavior) -> Result<Self> {
        let (setup, params, block_selection) = params.prepare(node)?;
        let bound = params.bound_node(node);
        let dealers = (0..node.num_nodes)
            .map(|dealer| {
                Ok(Dealer {
                    context: SharingContext::new(
                        &setup,
                        types::Instance {
                            session: bound.session_id,
                            epoch: params.epoch,
                            dealer,
                        },
                        b"csshashcoin/compact/v1".to_vec(),
                    )?,
                    public: None,
                    invalid_public: false,
                    pending_private: None,
                    receipt: None,
                    pending_tokens: BTreeMap::new(),
                    checked_tokens: Zeroizing::new(vec![None; node.num_nodes]),
                    checked_private: Zeroizing::new(None),
                    verified_weight: BigUint::zero(),
                    #[cfg(test)]
                    token_checks: 0,
                    #[cfg(test)]
                    recovery_attempts: 0,
                    tokens: vec![None; node.num_nodes],
                    echoed: false,
                    complete: false,
                    served: false,
                    value: None,
                    dirty: false,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            id: node.id,
            n: node.num_nodes,
            setup,
            range: params.range(),
            params,
            block_selection,
            behavior,
            dealers,
            gather: None,
            coefficients: None,
            started: false,
            coin: None,
            dirty_dealers: BTreeSet::new(),
            recovery_work: sdc_util::weighted_work::RecoveryQueue::new(node.num_nodes),
            cooperative_recovery: false,
            remaining: 0,
            #[cfg(test)]
            dealer_steps: 0,
            actions: vec![],
            events: vec![],
        })
    }
    /// Read-only, all-honest measurement predicate; not a protocol stop rule.
    pub fn service_progress(&self) -> sdc_util::observation::ServiceProgress {
        let pending = [
            (
                "sharing_completion",
                self.dealers.iter().filter(|d| !d.complete).count(),
            ),
            (
                "local_receipts",
                self.dealers.iter().filter(|d| d.receipt.is_none()).count(),
            ),
            (
                "local_public_files",
                self.dealers.iter().filter(|d| d.public.is_none()).count(),
            ),
            (
                "terminal_values",
                self.dealers.iter().filter(|d| d.value.is_none()).count(),
            ),
            (
                "token_services",
                self.dealers.iter().filter(|d| !d.served).count(),
            ),
            ("application_actions", self.actions.len()),
            ("scheduled_recovery", self.recovery_work.len()),
            (
                "nonhonest_behavior",
                usize::from(!matches!(self.behavior, Behavior::Honest)),
            ),
        ]
        .into_iter()
        .collect();
        sdc_util::observation::ServiceProgress::new(self.coin.is_some(), pending)
    }
    pub fn setup(&self) -> &Setup {
        &self.setup
    }
    pub fn coin(&self) -> Option<types::Coin> {
        self.coin
    }
    pub fn is_frozen(&self) -> bool {
        self.coefficients.is_some()
    }
    pub fn drain_actions(&mut self) -> Vec<Action> {
        std::mem::take(&mut self.actions)
    }
    pub fn drain_events(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.events)
    }
    pub fn global(&self) -> InstanceId {
        InstanceId::new(self.params.epoch, None, 0)
    }
    pub fn instance(&self, dealer: usize) -> InstanceId {
        InstanceId::new(self.params.epoch, Some(dealer), 0)
    }
    pub fn rbc_manifest(&self) -> Vec<wrbc::Request> {
        (0..self.n)
            .map(|d| wrbc::Request::Register {
                instance: self.instance(d),
                file_bytes: Public::encoded_len(&self.setup),
                coding: self.params.coding(),
            })
            .collect()
    }
    pub fn ra_manifest(&self) -> Vec<wra::Request> {
        (0..self.n)
            .map(|d| wra::Request::Expect {
                instance: self.instance(d),
            })
            .collect()
    }
    pub fn start(&mut self) -> Result<()> {
        ensure!(!self.started, "coin invocation already started");
        let (mut public, shares) = compact::share(
            &self.setup,
            &self.dealers[self.id].context,
            self.params.sample_message()?,
        )?;
        if matches!(self.behavior, Behavior::InvalidAx) {
            public.commitment[0] ^= 1;
        } else if matches!(self.behavior, Behavior::InvalidCorrections) {
            let corrections = public.base.corrections_mut();
            ensure!(!corrections.is_empty(), "CSS correction fixture needs OR gates");
            for block in corrections {
                block[0] ^= 1;
            }
        }
        self.started = true;
        self.events.push(Event::Started {
            public_bytes: public.byte_len(),
        });
        self.actions.push(Action::Gather(wgather::Request::Start {
            instance: self.global(),
        }));
        self.actions.push(Action::Rbc(wrbc::Request::Broadcast {
            instance: self.instance(self.id),
            data: public.encode(),
        }));
        for share in shares {
            self.actions.push(Action::Private {
                recipient: share.party,
                packet: Packet {
                    epoch: self.params.epoch,
                    dealer: self.id,
                    kind: PRIVATE,
                    payload: share.encode().to_vec(),
                },
            });
        }
        Ok(())
    }
    fn dealer_for(&self, instance: InstanceId) -> Option<usize> {
        if instance.epoch == self.params.epoch && instance.slot == 0 {
            instance.dealer.filter(|&d| d < self.n)
        } else {
            None
        }
    }
    fn deliver_public(&mut self, d: usize, file: wavid::ValidatedFile) {
        if self.dealers[d].public.is_some() || self.dealers[d].invalid_public {
            return;
        }
        match compact::PublicView::decode(&self.setup, &self.dealers[d].context, &file) {
            Ok(public) => {
                self.actions.push(Action::Ra(wra::Request::Register {
                    instance: self.instance(d),
                    header_id: public.digest(),
                }));
                let bytes = file.as_ref().len();
                sdc_util::observation::bulk_audit::add(d, if d == self.id && self.params.reuse_local_dealer { "local_reuse_bytes" } else { "remote_file_bytes" }, bytes);
                self.dealers[d].public = Some(file);
                self.dirty_dealers.insert(d);
                self.events
                    .push(Event::PublicDelivered { dealer: d, bytes });
            }
            Err(_) => self.dealers[d].invalid_public = true,
        }
    }
    pub fn rbc_event(&mut self, event: wrbc::Event) -> Result<()> {
        match event {
            wrbc::Event::Deliver { instance, data } => {
                if let Some(d) = self.dealer_for(instance) {
                    self.deliver_public(d, data);
                }
            }
            wrbc::Event::Invalid { instance, .. } => {
                if let Some(d) = self.dealer_for(instance) {
                    self.dealers[d].invalid_public = true;
                }
            }
            wrbc::Event::Rejected { reason, .. } => anyhow::bail!("WRBC: {reason}"),
            _ => {}
        }
        self.advance()
    }
    pub fn ra_event(&mut self, event: wra::Event) -> Result<()> {
        match event {
            wra::Event::Output {
                instance,
                value: true,
            } => {
                if let Some(d) = self.dealer_for(instance)
                    && self.dealers[d].public.is_some()
                    && !self.dealers[d].complete
                {
                    self.dealers[d].complete = true;
                    self.events.push(Event::Shared { dealer: d });
                    self.actions.push(Action::Gather(wgather::Request::Add {
                        instance: self.global(),
                        dealer: d,
                    }));
                }
            }
            wra::Event::Rejected { reason, .. } => anyhow::bail!("WRA: {reason}"),
            _ => {}
        }
        self.advance()
    }
    pub fn gather_event(&mut self, event: wgather::Event) -> Result<()> {
        match event {
            wgather::Event::DeliverSet { instance, dealers }
                if instance == self.global() && self.gather.is_none() =>
            {
                ensure!(
                    dealers
                        .iter()
                        .all(|&d| d < self.n && self.dealers[d].complete),
                    "Gather returned incomplete sharing"
                );
                let mut inputs = vec![false; self.n];
                for &d in &dealers {
                    inputs[d] = true;
                }
                self.gather = Some(dealers.clone());
                self.events.push(Event::Gathered { dealers });
                self.actions.push(Action::BinAa(wbinaa::Request::Start {
                    instance: self.global(),
                    inputs,
                }));
            }
            wgather::Event::Rejected { reason, .. } => anyhow::bail!("WGather: {reason}"),
            _ => {}
        }
        self.advance()
    }
    pub fn binaa_event(&mut self, event: wbinaa::Event) -> Result<()> {
        match event {
            wbinaa::Event::DeliverVector { instance, values }
                if instance == self.global() && self.coefficients.is_none() =>
            {
                ensure!(
                    self.gather.is_some() && values.len() == self.n,
                    "unexpected BinAA vector"
                );
                let max = wbinaa::protocol::round_count(&self.params.precision(self.n))?;
                ensure!(
                    values.iter().all(|x| x.exponent <= max
                        && BigUint::from_bytes_be(&x.numerator.0.to_bytes_be())
                            <= (BigUint::from(1u8) << x.exponent as usize)),
                    "invalid BinAA coefficient"
                );
                self.events.push(Event::Frozen {
                    numerators: values.iter().map(|x| x.numerator.to_string()).collect(),
                    exponents: values.iter().map(|x| x.exponent).collect(),
                });
                self.remaining = values
                    .iter()
                    .enumerate()
                    .filter(|(d, a)| !a.numerator.0.is_zero() && self.dealers[*d].value.is_none())
                    .count();
                self.recovery_work.set_priorities(
                    &values
                        .iter()
                        .map(|a| !a.numerator.0.is_zero())
                        .collect::<Vec<_>>(),
                );
                self.coefficients = Some(values);
                self.dirty_dealers.extend(0..self.n);
            }
            wbinaa::Event::Rejected { reason, .. } => anyhow::bail!("WBinAA: {reason}"),
            _ => {}
        }
        self.advance()
    }
    pub fn packet(&mut self, sender: usize, packet: Packet) -> Result<()> {
        let d = packet.dealer;
        if sender >= self.n || d >= self.n || packet.epoch != self.params.epoch {
            return Ok(());
        }
        let Ok(share) = PrivateShare::decode(&packet.payload) else {
            return Ok(());
        };
        if share.setup_id != self.setup.id() || share.context_id != self.dealers[d].context.id {
            return Ok(());
        }
        let dealer = &mut self.dealers[d];
        match packet.kind {
            PRIVATE
                if sender == d
                    && share.party == self.id
                    && dealer.receipt.is_none()
                    && *dealer.checked_private != Some(share.token) =>
            {
                dealer.pending_private = Some(share);
            }
            RECONSTRUCT
                if share.party == sender
                    && dealer.value.is_none()
                    && dealer.tokens[sender].is_none()
                    && dealer.checked_tokens[sender] != Some(share.token) =>
            {
                // One candidate per authenticated sender. Invalid input cannot poison another
                // party's slot; a later valid candidate can replace a rejected candidate.
                dealer.pending_tokens.insert(sender, share);
            }
            _ => return Ok(()),
        }
        self.dirty_dealers.insert(d);
        self.advance()
    }
    fn advance(&mut self) -> Result<()> {
        let _profile = sdc_util::profile::span("state.advance.csshashcoin");
        let frozen = self.coefficients.is_some();
        while let Some(d) = self.dirty_dealers.pop_first() {
            #[cfg(test)]
            {
                self.dealer_steps += 1;
            }
            let instance = self.instance(d);
            let dealer = &mut self.dealers[d];
            let Some(file) = &dealer.public else {
                continue;
            };
            let public = compact::PublicView::decode(&self.setup, &dealer.context, file)?;
            if let Some(candidate) = dealer.pending_private.take()
                && dealer.receipt.is_none()
                && *dealer.checked_private != Some(candidate.token)
            {
                *dealer.checked_private = Some(candidate.token);
                #[cfg(test)]
                {
                    dealer.token_checks += 1;
                }
                if public.verify_share(&candidate) {
                    dealer.receipt = Some(candidate);
                }
            }
            if dealer.receipt.is_some() && !dealer.echoed {
                dealer.echoed = true;
                self.actions.push(Action::Ra(wra::Request::Input {
                    instance,
                    value: true,
                }));
            }
            for (sender, candidate) in std::mem::take(&mut dealer.pending_tokens) {
                if dealer.tokens[sender].is_some()
                    || dealer.checked_tokens[sender] == Some(candidate.token)
                {
                    continue;
                }
                dealer.checked_tokens[sender] = Some(candidate.token);
                #[cfg(test)]
                {
                    dealer.token_checks += 1;
                }
                if dealer.receipt.as_ref().is_some_and(|own| own == &candidate)
                    || public.verify_share(&candidate)
                {
                    dealer.verified_weight += &self.setup.circuit().policy().weights()[sender];
                    dealer.tokens[sender] = Some(candidate);
                    dealer.dirty = true;
                }
            }
            // Send to EVERY party, also when our own coefficient is zero or coin is already out.
            if frozen
                && !dealer.served
                && let Some(receipt) = &dealer.receipt
            {
                dealer.served = true;
                if !matches!(self.behavior, Behavior::WithholdRecovery) {
                    let mut sent = receipt.clone();
                    if matches!(self.behavior, Behavior::InvalidRecovery) {
                        sent.token[0] ^= 1;
                    }
                    let encoded = sent.encode();
                    for recipient in 0..self.n {
                        self.actions.push(Action::Recovery {
                            recipient,
                            packet: Packet {
                                epoch: self.params.epoch,
                                dealer: d,
                                kind: RECONSTRUCT,
                                payload: encoded.to_vec(),
                            },
                        });
                    }
                    self.events.push(Event::TokenReleased { dealer: d });
                }
            }
            if self.cooperative_recovery {
                if frozen
                    && dealer.value.is_none()
                    && dealer.dirty
                    && dealer.verified_weight >= *self.setup.circuit().policy().threshold()
                {
                    self.recovery_work.wake(d);
                }
            } else {
                self.recover_one(d)?;
            }
        }
        self.try_output()
    }
    pub(crate) fn enable_cooperative_recovery(&mut self) {
        self.cooperative_recovery = true;
    }
    pub(crate) fn recovery_pending(&self) -> bool {
        !self.recovery_work.is_empty()
    }
    pub(crate) fn resume_recovery(&mut self) -> Result<()> {
        if let Some(d) = self.recovery_work.pop() {
            self.recover_one(d)?;
        }
        self.try_output()
    }
    fn recover_one(&mut self, d: usize) -> Result<()> {
        let frozen = self.coefficients.is_some();
        let range = &self.range;
        let dealer = &mut self.dealers[d];
        let Some(file) = &dealer.public else {
            return Ok(());
        };
        let public = compact::PublicView::decode(&self.setup, &dealer.context, file)?;
        if frozen && dealer.value.is_none() && dealer.dirty {
            dealer.dirty = false;
            if dealer.verified_weight < *self.setup.circuit().policy().threshold() {
                return Ok(());
            }
            #[cfg(test)]
            {
                dealer.recovery_attempts += 1;
            }
            match public.reconstruct(&self.setup, &dealer.context, dealer.tokens.iter().flatten()) {
                Ok(recovered) => {
                    let value = BigUint::from_bytes_be(&recovered.opening.message);
                    let rejected = &value >= range;
                    let value = if rejected { BigUint::zero() } else { value };
                    self.events.push(Event::Reconstructed {
                        dealer: d,
                        rejected,
                        value: value.to_string(),
                    });
                    dealer.value = Some(value);
                }
                Err(types::Error::InsufficientShares) => {}
                Err(types::Error::InvalidCommitment) => {
                    dealer.value = Some(BigUint::zero());
                    self.events.push(Event::Reconstructed {
                        dealer: d,
                        rejected: true,
                        value: "0".to_string(),
                    });
                }
                Err(error) => return Err(error.into()),
            }
            if dealer.value.is_some() {
                if !self.coefficients.as_ref().unwrap()[d].numerator.0.is_zero() {
                    self.remaining -= 1;
                }
                dealer.tokens = Vec::new();
                dealer.pending_tokens.clear();
                dealer.checked_tokens = Zeroizing::new(Vec::new());
            }
        }
        Ok(())
    }
    fn try_output(&mut self) -> Result<()> {
        if self.coin.is_none()
            && self.remaining == 0
            && let Some(coefficients) = &self.coefficients
            && let Some(value) = whcc::aggregate::aggregate_borrowed(
                coefficients,
                self.dealers.iter().map(|d| d.value.as_ref()),
                self.params.rounding_bits,
                self.params.output_bits,
            )?
        {
            self.coin = Some(value);
            self.events.push(Event::Coin {
                epoch: self.params.epoch,
                value,
            });
            self.events.push(Event::Complete);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
