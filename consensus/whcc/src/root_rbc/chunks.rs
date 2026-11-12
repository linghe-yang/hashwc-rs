//! Pre-registered 64 B broadcasts; expose one logical list only after ALL chunks.
use super::{Message, State};
use anyhow::{Result, ensure};
use recovery::ranked::{self, Block};
use sdc_types::{InstanceId, SendAction, WeightedMembership};
use std::collections::BTreeMap;

struct Assembly {
    blocks: Vec<Option<Block>>,
    remaining: usize,
    started: bool,
}
#[derive(Clone, Debug)]
pub struct Event {
    pub instance: InstanceId,
    pub data: Vec<u8>,
}
pub struct Lists {
    epoch: u64,
    states: BTreeMap<InstanceId, State<Block>>,
    assemblies: BTreeMap<usize, Assembly>,
    pub outgoing: Vec<SendAction<Message>>,
    pub events: Vec<Event>,
}
impl Lists {
    pub fn new(
        membership: WeightedMembership,
        id: usize,
        epoch: u64,
        lengths: &[usize],
    ) -> Result<Self> {
        ensure!(
            lengths.is_empty() || lengths.len() == membership.n(),
            "list manifest dimensions"
        );
        ensure!(
            lengths
                .iter()
                .all(|&l| l > 0 && l % ranked::BLOCK_BYTES == 0),
            "list manifest lengths"
        );
        let count: usize = lengths.iter().map(|l| l / ranked::BLOCK_BYTES).sum();
        ensure!(
            count <= sdc_util::weighted::MAX_INSTANCES,
            "list chunk instance limit"
        );
        let mut states = BTreeMap::new();
        let mut assemblies = BTreeMap::new();
        for (dealer, &length) in lengths.iter().enumerate() {
            let blocks = length / ranked::BLOCK_BYTES;
            for j in 0..blocks {
                let instance = InstanceId::new(epoch, Some(dealer), 1 + j as u64);
                states.insert(
                    instance,
                    State::<Block>::new(membership.clone(), id, instance)?,
                );
            }
            assemblies.insert(
                dealer,
                Assembly {
                    blocks: vec![None; blocks],
                    remaining: blocks,
                    started: false,
                },
            );
        }
        Ok(Self {
            epoch,
            states,
            assemblies,
            outgoing: vec![],
            events: vec![],
        })
    }
    pub fn instance_count(&self) -> usize {
        self.states.len()
    }
    pub fn broadcast(&mut self, instance: InstanceId, data: &[u8]) -> Result<()> {
        ensure!(
            instance.epoch == self.epoch && instance.slot == 1,
            "logical list instance"
        );
        let dealer = instance
            .dealer
            .ok_or_else(|| anyhow::anyhow!("missing list dealer"))?;
        let assembly = self
            .assemblies
            .get_mut(&dealer)
            .ok_or_else(|| anyhow::anyhow!("unregistered list"))?;
        ensure!(
            !assembly.started && data.len() == assembly.blocks.len() * ranked::BLOCK_BYTES,
            "list start/length"
        );
        // Check authorization before making any state mutation.
        let parts = ranked::split(data)?;
        for (j, block) in parts.into_iter().enumerate() {
            let slot = InstanceId::new(self.epoch, Some(dealer), 1 + j as u64);
            self.states.get_mut(&slot).unwrap().broadcast(block)?;
            self.flush(slot);
        }
        self.assemblies.get_mut(&dealer).unwrap().started = true;
        Ok(())
    }
    pub fn receive(&mut self, sender: usize, message: Message) {
        let instance = message.instance;
        if let Some(state) = self.states.get_mut(&instance) {
            state.receive(sender, message);
            self.flush(instance);
        }
        // Unknown epochs, dealers and surplus slots never allocate state.
    }
    fn flush(&mut self, instance: InstanceId) {
        let state = self.states.get_mut(&instance).unwrap();
        self.outgoing.append(&mut state.outgoing);
        for event in std::mem::take(&mut state.events) {
            let dealer = event.instance.dealer.unwrap();
            let assembly = self.assemblies.get_mut(&dealer).unwrap();
            let slot = event.instance.slot as usize - 1;
            if assembly.blocks[slot].is_none() {
                assembly.blocks[slot] = Some(event.block);
                assembly.remaining -= 1;
                if assembly.remaining == 0 {
                    self.events.push(Event {
                        instance: InstanceId::new(self.epoch, Some(dealer), 1),
                        data: ranked::join(assembly.blocks.iter().map(|b| b.unwrap())),
                    });
                }
            }
        }
        // Keep voting/service state alive after local delivery.
    }
}
