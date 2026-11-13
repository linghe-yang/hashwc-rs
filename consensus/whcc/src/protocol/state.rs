use super::work::DealerQueue;
use crate::{
    Parameters,
    aggregate::aggregate_borrowed,
    msg::{Action, Event, PRIVATE_TOKEN},
};
use anyhow::{Result, ensure};
use network::Packet;
use num_bigint::BigUint;
use num_traits::Zero;
use sdc_config::Node;
use sdc_types::{Dyadic, InstanceId};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use wcss::Setup;
use wiawvss::certified::{Header, Receipt};
use wiawvss::{Context as SharingContext, Opening, PrivateShare, Public, ax};

pub struct Dealer {
    pub context: SharingContext,
    pub recovery_cache: Option<wiawvss::IncrementalRecovery>,
    pub header: Option<Header>,
    pub codec: Arc<wavid::Codec>,
    pub stored_root: Option<[u8; 32]>,
    pub echoed: bool,
    pub retrieving: bool,
    pub file: Option<wavid::ValidatedFile>,
    pub material: Option<wavid::VerifiedMaterial>,
    pub storage_terminal: Option<wiawvss::certified::Certificate>,
    pub receipt: Option<PrivateShare>,
    pub pending_receipt: Option<Receipt>,
    pub complete: bool,
    pub rejected_public: bool,
    pub served: Vec<bool>,
    pub(super) pending_recipients: BTreeSet<usize>,
    pub tokens: BTreeMap<usize, PrivateShare>,
    pub pending_terminals: BTreeMap<usize, Vec<u8>>,
    pub(super) ready_terminals: BTreeSet<usize>,
    pub rejected_terminals: recovery::RejectedEvidence,
    pub terminal_seen: Vec<bool>,
    pub terminal_sent: bool,
    pub recovery_dirty: bool,
    pub terminal: Option<Vec<u8>>,
    pub value: Option<BigUint>,
}
pub struct State {
    pub behavior: crate::Behavior,
    pub id: usize,
    pub n: usize,
    pub setup: Arc<Setup>,
    pub params: Parameters,
    pub block_selection: wiawvss::blocksize::Selection,
    pub context_id: [u8; 32],
    pub sampling: recovery::Parameters,
    pub assignments: recovery::Assignments,
    pub group_plan: Option<recovery::GroupPlan>,
    pub(super) local_material: Option<super::local::LocalMaterial>,
    pub dealers: Vec<Dealer>,
    pub coefficients: Option<Vec<Dyadic>>,
    pub(super) work: DealerQueue,
    pub(super) recovery_work: sdc_util::weighted_work::RecoveryQueue,
    pub(super) cooperative_recovery: bool,
    /// Pending terminal dealers indexed by the sender whose list is missing.
    pub(super) terminal_waiters: Vec<BTreeSet<usize>>,
    /// Positive-coefficient dealers still lacking a value, initialized at Freeze.
    pub(super) remaining: Option<usize>,
    #[cfg(test)]
    pub(super) dealer_visits: Vec<usize>,
    #[cfg(test)]
    pub(super) aggregation_runs: usize,
    pub gather: Option<Vec<usize>>,
    pub started: bool,
    pub coin: Option<types::Coin>,
    pub actions: Vec<Action>,
    pub events: Vec<Event>,
}
impl State {
    pub fn new(node: &Node, params: Parameters) -> Result<Self> {
        let (setup, params, block_selection) = params.prepare(node)?;
        let setup = Arc::new(setup);
        let context_id = params.context_id(node, &setup);
        let sampling = params.sampling(&setup)?;
        let group_plan = params.group_plan(&setup)?;
        let mut assignments = recovery::Assignments::new(sampling.clone(), context_id);
        if let Some(plan) = &group_plan {
            assignments.lists = plan.lists().into_iter().map(Some).collect();
        }
        let reuse = params.reuse_local_dealer;
        let avid_public_id = params.bound_node(node, &setup).weighted_public_id("wavid");
        let membership = node.weighted_membership()?;
        let dealers = (0..node.num_nodes)
            .map(|dealer| {
                Ok(Dealer {
                    context: SharingContext::new(
                        &setup,
                        types::Instance {
                            session: node.session_id,
                            epoch: params.epoch,
                            dealer,
                        },
                        context_id.to_vec(),
                    )?,
                    recovery_cache: None,
                    header: None,
                    codec: Arc::new(wavid::Codec::with_params(
                        &membership,
                        sdc_types::InstanceId::new(params.epoch, Some(dealer), 0),
                        avid_public_id,
                        Public::encoded_len(&setup),
                        params.bulk_coding(),
                    )?),
                    stored_root: None,
                    echoed: false,
                    retrieving: false,
                    file: None,
                    material: None,
                    storage_terminal: None,
                    receipt: None,
                    pending_receipt: None,
                    complete: false,
                    rejected_public: false,
                    served: vec![false; node.num_nodes],
                    pending_recipients: (0..node.num_nodes)
                        .filter(|&i| assignments.authorized(i, dealer) && !(reuse && i == dealer))
                        .collect(),
                    tokens: BTreeMap::new(),
                    pending_terminals: BTreeMap::new(),
                    ready_terminals: BTreeSet::new(),
                    rejected_terminals: recovery::RejectedEvidence::default(),
                    terminal_seen: vec![false; node.num_nodes],
                    terminal_sent: false,
                    recovery_dirty: true,
                    terminal: None,
                    value: None,
                })
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            behavior: crate::Behavior::Honest,
            id: node.id,
            n: node.num_nodes,
            setup,
            params,
            block_selection,
            context_id,
            sampling,
            assignments,
            group_plan,
            local_material: None,
            dealers,
            coefficients: None,
            work: DealerQueue::new(node.num_nodes),
            recovery_work: sdc_util::weighted_work::RecoveryQueue::new(node.num_nodes),
            cooperative_recovery: false,
            terminal_waiters: vec![BTreeSet::new(); node.num_nodes],
            remaining: None,
            #[cfg(test)]
            dealer_visits: vec![0; node.num_nodes],
            #[cfg(test)]
            aggregation_runs: 0,
            gather: None,
            started: false,
            coin: None,
            actions: vec![],
            events: vec![],
        })
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
    pub fn instance(&self, dealer: usize, slot: u64) -> InstanceId {
        InstanceId::new(self.params.epoch, Some(dealer), slot)
    }
    pub fn global(&self) -> InstanceId {
        InstanceId::new(self.params.epoch, None, 0)
    }
    pub fn reuses_local_dealer(&self) -> bool {
        self.params.reuse_local_dealer
    }
    /// K_d authorizes terminals; N_d authorizes public bulk and private tokens.
    pub fn remote_authorized(&self, party: usize, dealer: usize) -> bool {
        self.assignments.authorized(party, dealer)
            && !(self.reuses_local_dealer() && party == dealer)
    }
    pub fn list_chunk_lengths(&self) -> Vec<usize> {
        if self.group_plan.is_some()
            || self.params.list_broadcast == super::parameters::ListBroadcast::CodedV1
        {
            return vec![];
        }
        self.sampling
            .quotas
            .iter()
            .map(|&d| {
                recovery::ranked::Codec::new(self.n, d)
                    .expect("quota")
                    .encoded_len()
            })
            .collect()
    }
    pub fn encode_sampling_list(&self, party: usize, list: &[usize]) -> Result<Vec<u8>> {
        anyhow::ensure!(party < self.n, "unknown list party");
        match self.params.list_broadcast {
            super::parameters::ListBroadcast::FixedChunksV1 => {
                recovery::ranked::Codec::new(self.n, self.sampling.quotas[party])?
                    .encode(self.context_id, list)
            }
            super::parameters::ListBroadcast::CodedV1 => {
                self.sampling.encode(self.context_id, party, list)
            }
        }
    }
    /// Only coded instances. Fixed list chunks have a separate public manifest.
    pub fn rbc_manifest(&self) -> Vec<wrbc::Request> {
        let mut out = vec![];
        for d in 0..self.n {
            if !self.params.short_root_rbc {
                out.push(wrbc::Request::Register {
                    coding: Parameters::CONTROL_CODING,
                    instance: self.instance(d, 0),
                    file_bytes: Header::BYTES,
                });
            }
            if self.group_plan.is_none()
                && self.params.list_broadcast == super::parameters::ListBroadcast::CodedV1
            {
                out.push(wrbc::Request::Register {
                    coding: Parameters::CONTROL_CODING,
                    instance: self.instance(d, 1),
                    file_bytes: self.sampling.encoded_len(d),
                });
            }
        }
        out
    }
    pub fn avid_manifest(&self) -> Vec<wavid::Request> {
        (0..self.n)
            .map(|d| wavid::Request::Register {
                instance: self.instance(d, 0),
                descriptor: wavid::Descriptor {
                    coding: self.params.bulk_coding(),
                    file_bytes: Public::encoded_len(&self.setup),
                    root: None,
                    retrievers: (0..self.n)
                        .filter(|&i| self.remote_authorized(i, d))
                        .collect(),
                    completion: wavid::CompletionMode::External,
                },
            })
            .collect()
    }
    pub fn ra_manifest(&self) -> Vec<wra::Request> {
        (0..self.n)
            .map(|d| wra::Request::Expect {
                instance: self.instance(d, 0),
            })
            .collect()
    }
    pub fn start(&mut self) -> Result<()> {
        ensure!(!self.started, "common coin invocation already started");
        // Keep the original independent draw: never force a self edge.
        let list = if self.group_plan.is_some() {
            vec![]
        } else {
            self.sampling.sample(self.id)?
        };
        self.start_with_list(list)
    }
    /// The list is an actual sampling result, not an authorization. Only its
    /// complete RBC delivery can authorize use of the retained local opening.
    pub(super) fn start_with_list(&mut self, list: Vec<usize>) -> Result<()> {
        ensure!(!self.started, "common coin invocation already started");
        let self_selected = if self.group_plan.is_some() {
            self.assignments.authorized(self.id, self.id)
        } else {
            list.contains(&self.id)
        };
        if self.reuses_local_dealer() && self_selected && self.behavior == crate::Behavior::Honest {
            let (local, prepared, shares) = super::local::LocalMaterial::generate(
                &self.setup,
                &self.dealers[self.id].context,
                &self.dealers[self.id].codec,
                &self.params,
            )?;
            let declaration = if self.group_plan.is_some() {
                None
            } else {
                Some(self.encode_sampling_list(self.id, &list)?)
            };
            self.local_material = Some(local);
            self.start_prepared(declaration, prepared, shares)?;
            self.work.wake(self.id);
            return self.advance();
        }
        // Independent OS randomness for AX; supplied/faulted material never
        // acquires the local honest-generation provenance used above.
        let opening = Opening {
            message: self.params.sample_message()?,
            randomness: crypto::random().map_err(|e| anyhow::anyhow!("randomness: {e}"))?,
        };
        let (mut public, shares) =
            ax::generate(&self.setup, &self.dealers[self.id].context, &opening)?;
        if self.behavior == crate::Behavior::InvalidCorrections {
            anyhow::ensure!(!public.base.corrections.is_empty(), "CSS correction fixture needs OR gates");
        }
        self.behavior.corrupt_public(&mut public);
        self.start_material(list, public, shares)
    }
    pub(super) fn start_material(
        &mut self,
        list: Vec<usize>,
        public: Public,
        shares: Vec<PrivateShare>,
    ) -> Result<()> {
        ensure!(!self.started, "common coin invocation already started");
        let declaration = if self.group_plan.is_some() {
            None
        } else {
            Some(self.encode_sampling_list(self.id, &list)?)
        };
        let codec = &self.dealers[self.id].codec;
        let prepared = codec.prepare_dispersal(
            public.encode(),
            &wiawvss::certified::receipt_blocks(&self.setup, codec),
        )?;
        self.start_prepared(declaration, prepared, shares)
    }
    fn start_prepared(
        &mut self,
        declaration: Option<Vec<u8>>,
        prepared: wavid::Dispersal,
        shares: Vec<PrivateShare>,
    ) -> Result<()> {
        ensure!(!self.started, "common coin invocation already started");
        let header = Header::new(
            &self.setup,
            &self.dealers[self.id].context,
            prepared.file().root(),
        );
        self.started = true;
        self.actions.push(Action::Gather(wgather::Request::Start {
            instance: self.global(),
        }));
        if let Some(data) = declaration {
            self.actions.push(Action::Rbc(wrbc::Request::Broadcast {
                instance: self.instance(self.id, 1),
                data,
            }));
        }
        if self.params.short_root_rbc {
            self.actions.push(Action::RootRbc(crate::root_rbc::Request {
                instance: self.instance(self.id, 0),
                root: header.root,
            }));
        } else {
            self.actions.push(Action::Rbc(wrbc::Request::Broadcast {
                instance: self.instance(self.id, 0),
                data: header.encode(),
            }));
        }

        self.actions
            .push(Action::Avid(wavid::Request::DisperseCached {
                instance: self.instance(self.id, 0),
                prepared: prepared.clone(),
            }));
        for share in shares {
            self.actions.push(Action::Private {
                recipient: share.party,
                packet: Packet {
                    epoch: self.params.epoch,
                    dealer: self.id,
                    kind: PRIVATE_TOKEN,
                    payload: Receipt::new(
                        &self.setup,
                        &self.dealers[self.id].codec,
                        &prepared,
                        &share,
                    )?
                    .encode(),
                },
            });
        }
        Ok(())
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
                    "Gather returned locally invalid dealer"
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
                    "invalid BinAA output"
                );
                self.events.push(Event::Frozen {
                    coefficients: values.clone(),
                });
                self.remaining = Some(
                    values
                        .iter()
                        .zip(&self.dealers)
                        .filter(|(a, d)| !a.numerator.0.is_zero() && d.value.is_none())
                        .count(),
                );
                self.recovery_work.set_priorities(
                    &values
                        .iter()
                        .map(|a| !a.numerator.0.is_zero())
                        .collect::<Vec<_>>(),
                );
                self.coefficients = Some(values);
                // Freeze enables private service for ALL dealers, including zero
                // coefficients and dealers which complete only later.
                for d in 0..self.n {
                    self.work.wake(d);
                }
            }
            wbinaa::Event::Rejected { reason, .. } => anyhow::bail!("WBinAA: {reason}"),
            _ => {}
        }
        self.advance()
    }
    /// Runtime-only scheduling: the synchronous state API remains useful for
    /// deterministic simulations. Both modes use the same gates and messages.
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
    pub(super) fn advance(&mut self) -> Result<()> {
        let _profile = sdc_util::profile::span("state.advance.whcc");
        while let Some(d) = self.work.pop() {
            #[cfg(test)]
            {
                self.dealer_visits[d] += 1;
            }
            self.receipts(d)?;
            self.release_recovery_tokens(d);
            if self.cooperative_recovery {
                if self.coefficients.is_some()
                    && self.dealers[d].complete
                    && (self.dealers[d].value.is_none() || !self.dealers[d].terminal_sent)
                {
                    self.recovery_work.wake(d);
                }
            } else {
                self.recover_one(d)?;
            }
        }
        self.try_output()
    }
    fn recover_one(&mut self, d: usize) -> Result<()> {
        let _profile = sdc_util::profile::span("state.dealer.whcc");
        let had_value = self.dealers[d].value.is_some();
        self.recovery(d)?;
        if self.cooperative_recovery
            && self.dealers[d].value.is_none()
            && !self.dealers[d].ready_terminals.is_empty()
        {
            self.recovery_work.wake(d);
        }
        if !had_value && self.dealers[d].value.is_some() {
            // Keep the private receipt, root-bound file, and terminal needed by
            // late peers; only the now-useless reconstruction scratch is dropped.
            let dealer = &mut self.dealers[d];
            dealer.recovery_cache = None;
            dealer.tokens.clear();
            dealer.pending_terminals.clear();
            dealer.ready_terminals.clear();
            dealer.rejected_terminals = recovery::RejectedEvidence::default();
            dealer.recovery_dirty = false;
            for waiters in &mut self.terminal_waiters {
                waiters.remove(&d);
            }
        }
        // First-terminal transition is atomic within this synchronous turn.
        // Later certificates, duplicates, and zero coefficients cannot decrement.
        if !had_value
            && self.dealers[d].value.is_some()
            && self
                .coefficients
                .as_ref()
                .is_some_and(|a| !a[d].numerator.0.is_zero())
        {
            let remaining = self
                .remaining
                .as_mut()
                .expect("Freeze initializes remaining");
            *remaining = remaining
                .checked_sub(1)
                .ok_or_else(|| anyhow::anyhow!("remaining contribution count underflow"))?;
        }
        Ok(())
    }
    fn try_output(&mut self) -> Result<()> {
        if self.coin.is_none() && self.remaining == Some(0) {
            let _aggregate_profile = sdc_util::profile::span("state.aggregate.whcc");
            #[cfg(test)]
            {
                self.aggregation_runs += 1;
            }
            let value = aggregate_borrowed(
                self.coefficients
                    .as_ref()
                    .expect("Freeze initializes remaining"),
                self.dealers.iter().map(|d| d.value.as_ref()),
                self.params.rounding_bits,
                self.params.output_bits,
            )?
            .ok_or_else(|| anyhow::anyhow!("remaining count omitted a required contribution"))?;
            self.coin = Some(value);
            self.events.push(Event::Coin {
                epoch: self.params.epoch,
                value,
            });
        }
        Ok(())
    }
}
