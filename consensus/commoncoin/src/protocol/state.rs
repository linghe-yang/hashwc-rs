use crate::{
    Parameters,
    aggregate::aggregate,
    msg::{Action, Event, PRIVATE_TOKEN},
};
use anyhow::{Result, ensure};
use network::Packet;
use num_bigint::BigUint;
use sdc_config::Node;
use sdc_types::{Dyadic, InstanceId};
use std::{collections::BTreeMap, sync::Arc};
use wcss::Setup;
use wiawvss::{Context as SharingContext, Opening, PrivateShare, Public, ax};

pub struct Dealer {
    pub context: SharingContext,
    pub public: Option<Public>,
    pub receipt: Option<PrivateShare>,
    pub pending_receipt: Option<PrivateShare>,
    pub complete: bool,
    pub rejected_public: bool,
    pub served: Vec<bool>,
    pub tokens: BTreeMap<usize, PrivateShare>,
    pub pending_terminals: BTreeMap<usize, Vec<u8>>,
    pub terminal_seen: Vec<bool>,
    pub terminal_sent: bool,
    pub recovery_dirty: bool,
    pub terminal: Option<Vec<u8>>,
    pub value: Option<BigUint>,
}
pub struct State {
    pub id: usize,
    pub n: usize,
    pub setup: Arc<Setup>,
    pub params: Parameters,
    pub context_id: [u8; 32],
    pub sampling: recovery::Parameters,
    pub assignments: recovery::Assignments,
    pub dealers: Vec<Dealer>,
    pub coefficients: Option<Vec<Dyadic>>,
    pub gather: Option<Vec<usize>>,
    pub started: bool,
    pub coin: Option<types::Coin>,
    pub actions: Vec<Action>,
    pub events: Vec<Event>,
}
impl State {
    pub fn new(node: &Node, params: Parameters) -> Result<Self> {
        let setup = Arc::new(params.setup(node)?);
        let context_id = params.context_id(node, &setup);
        let sampling = recovery::Parameters::new(setup.circuit().policy(), params.coverage_bits)?;
        let assignments = recovery::Assignments::new(sampling.clone(), context_id);
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
                    public: None,
                    receipt: None,
                    pending_receipt: None,
                    complete: false,
                    rejected_public: false,
                    served: vec![false; node.num_nodes],
                    tokens: BTreeMap::new(),
                    pending_terminals: BTreeMap::new(),
                    terminal_seen: vec![false; node.num_nodes],
                    terminal_sent: false,
                    recovery_dirty: true,
                    terminal: None,
                    value: None,
                })
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            id: node.id,
            n: node.num_nodes,
            setup,
            params,
            context_id,
            sampling,
            assignments,
            dealers,
            coefficients: None,
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
    pub fn rbc_manifest(&self) -> Vec<wrbc::Request> {
        (0..self.n)
            .flat_map(|d| {
                [
                    wrbc::Request::Register {
                        instance: self.instance(d, 0),
                        file_bytes: Public::encoded_len(&self.setup),
                    },
                    wrbc::Request::Register {
                        instance: self.instance(d, 1),
                        file_bytes: self.sampling.encoded_len(d),
                    },
                ]
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
        // Independent OS randomness for assignments, message, and AX randomness.
        let list = self.sampling.sample(self.id)?;
        let opening = Opening {
            message: self.params.sample_message()?,
            randomness: crypto::random().map_err(|e| anyhow::anyhow!("randomness: {e}"))?,
        };
        let (public, shares) = ax::generate(&self.setup, &self.dealers[self.id].context, &opening)?;
        self.start_material(list, public, shares)
    }
    pub(super) fn start_material(
        &mut self,
        list: Vec<usize>,
        public: Public,
        shares: Vec<PrivateShare>,
    ) -> Result<()> {
        ensure!(!self.started, "common coin invocation already started");
        let declaration = self.sampling.encode(self.context_id, self.id, &list)?;
        self.started = true;
        self.actions.push(Action::Gather(wgather::Request::Start {
            instance: self.global(),
        }));
        self.actions.push(Action::Rbc(wrbc::Request::Broadcast {
            instance: self.instance(self.id, 1),
            data: declaration,
        }));
        self.actions.push(Action::Rbc(wrbc::Request::Broadcast {
            instance: self.instance(self.id, 0),
            data: public.encode(),
        }));
        for share in shares {
            self.actions.push(Action::Private {
                recipient: share.party,
                packet: Packet {
                    epoch: self.params.epoch,
                    dealer: self.id,
                    kind: PRIVATE_TOKEN,
                    payload: share.encode().to_vec(),
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
                self.coefficients = Some(values);
            }
            wbinaa::Event::Rejected { reason, .. } => anyhow::bail!("WBinAA: {reason}"),
            _ => {}
        }
        self.advance()
    }
    pub(super) fn advance(&mut self) -> Result<()> {
        self.receipts()?;
        self.recovery()?;
        if self.coin.is_none()
            && let Some(coefficients) = &self.coefficients
        {
            let values = self
                .dealers
                .iter()
                .map(|d| d.value.clone())
                .collect::<Vec<_>>();
            if let Some(value) = aggregate(
                coefficients,
                &values,
                self.params.rounding_bits,
                self.params.output_bits,
            )? {
                self.coin = Some(value);
                self.events.push(Event::Coin {
                    epoch: self.params.epoch,
                    value,
                });
            }
        }
        Ok(())
    }
}
