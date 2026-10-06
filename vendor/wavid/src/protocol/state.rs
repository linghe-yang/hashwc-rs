use crate::{Codec, CompletionMode, Descriptor, Event, Kind, ProtMsg, Retrieval, CHUNK_BYTES};
use anyhow::{ensure, Result};
use crypto::hash::Hash;
use num_bigint::BigUint;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use types::{InstanceId, Replica, SendAction, WeightedMembership};

/// A bounded slot per authenticated sender: invalid chunks cannot create unbounded work.
pub(crate) struct Assembly {
    total: usize,
    parts: BTreeMap<u32, Vec<u8>>,
    closed: bool,
}
impl Assembly {
    pub fn new(total: usize) -> Self {
        Self {
            total,
            parts: BTreeMap::new(),
            closed: false,
        }
    }
    pub fn add(&mut self, index: u32, bytes: Vec<u8>) -> Option<Vec<u8>> {
        if self.closed {
            return None;
        }
        let start = index as usize * CHUNK_BYTES;
        if start >= self.total || bytes.len() != CHUNK_BYTES.min(self.total - start) {
            self.closed = true;
            self.parts.clear();
            return None;
        }
        self.parts.entry(index).or_insert(bytes);
        if self.parts.len() == self.total.div_ceil(CHUNK_BYTES) {
            self.closed = true;
            let mut raw = Vec::with_capacity(self.total);
            for (_, part) in std::mem::take(&mut self.parts) {
                raw.extend(part);
            }
            return Some(raw);
        }
        None
    }
}
pub struct State {
    pub membership: WeightedMembership,
    pub id: Replica,
    pub instance: InstanceId,
    pub codec: Codec,
    pub descriptor: Descriptor,
    pub stored_root: Option<Hash>,
    pub completed_root: Option<Hash>,
    pub ready_root: Option<Hash>,
    pub result: Option<Retrieval>,
    pub outgoing: Vec<SendAction<ProtMsg>>,
    pub events: Vec<Event>,
    pub(crate) init: Assembly,
    pub(crate) data_slots: HashMap<Replica, super::stream::DataStream>,
    pub(crate) unpinned_packet: Option<Vec<u8>>,
    pub(crate) stored_packet: Option<std::sync::Arc<Vec<u8>>>,
    pub(crate) recovery: Option<super::stream::Recovery>,
    pub(crate) rows: Vec<BTreeMap<usize, super::codec::StoredFragment>>,
    pub(crate) acks: HashMap<Replica, Hash>,
    pub(crate) readies: HashMap<Replica, Hash>,
    pub ack_weights: BTreeMap<Hash, BigUint>,
    pub ready_weights: BTreeMap<Hash, BigUint>,
    pub(crate) requests: HashMap<Replica, Hash>,
    pub(crate) served: BTreeSet<Replica>,
    pub(crate) retrievers: BTreeSet<Replica>,
    pub(crate) want: bool,
    pub(crate) asked: bool,
    pub(crate) dispersed: bool,
}
impl State {
    pub fn new(
        membership: WeightedMembership,
        id: Replica,
        instance: InstanceId,
        public_id: Hash,
        descriptor: Descriptor,
    ) -> Result<Self> {
        ensure!(id < membership.n(), "invalid local ID");
        membership
            .weight(descriptor.retrievers.iter().copied())
            .map_err(anyhow::Error::msg)?;
        let codec = Codec::with_params(
            &membership,
            instance,
            public_id,
            descriptor.file_bytes,
            descriptor.coding,
        )?;
        ensure!(
            (0..membership.n())
                .all(|p| codec.bundle_bytes(p).div_ceil(CHUNK_BYTES) <= u32::MAX as usize),
            "fragment index capacity"
        );
        let init = Assembly::new(codec.bundle_bytes(id));
        let rows = (0..codec.q).map(|_| BTreeMap::new()).collect();
        let retrievers = descriptor.retrievers.iter().copied().collect();
        Ok(Self {
            membership,
            id,
            instance,
            codec,
            descriptor,
            stored_root: None,
            completed_root: None,
            ready_root: None,
            result: None,
            outgoing: vec![],
            events: vec![],
            init,
            data_slots: HashMap::new(),
            unpinned_packet: None,
            stored_packet: None,
            recovery: None,
            rows,
            acks: HashMap::new(),
            readies: HashMap::new(),
            ack_weights: BTreeMap::new(),
            ready_weights: BTreeMap::new(),
            requests: HashMap::new(),
            served: BTreeSet::new(),
            retrievers,
            want: false,
            asked: false,
            dispersed: false,
        })
    }
    pub(crate) fn send(&mut self, recipient: Replica, kind: Kind) {
        self.outgoing.push(SendAction {
            recipient,
            message: ProtMsg {
                instance: self.instance,
                kind,
            },
        });
    }
    pub(crate) fn broadcast(&mut self, kind: Kind) {
        for peer in 0..self.membership.n() {
            self.send(peer, kind.clone());
        }
    }
    pub(crate) fn packet(&mut self, peer: Replica, data: bool, raw: &[u8]) {
        for (index, bytes) in raw.chunks(CHUNK_BYTES).enumerate() {
            self.send(
                peer,
                if data {
                    Kind::Data {
                        index: index as u32,
                        bytes: bytes.to_vec(),
                    }
                } else {
                    Kind::Init {
                        index: index as u32,
                        bytes: bytes.to_vec(),
                    }
                },
            );
        }
    }
    /// The application pins a root authenticated by its higher-level broadcast.
    pub fn pin_root(&mut self, root: Hash) -> Result<()> {
        ensure!(
            self.descriptor.completion == CompletionMode::External,
            "pinning is for external completion"
        );
        ensure!(
            self.descriptor.root.is_none_or(|r| r == root),
            "root already pinned differently"
        );
        self.descriptor.root = Some(root);
        if let Some(raw) = self.unpinned_packet.take() {
            self.store_packet(raw);
        }
        self.advance();
        Ok(())
    }
    fn store_packet(&mut self, raw: Vec<u8>) {
        if let Some(root) = self
            .codec
            .verify_packet(self.id, &raw, self.descriptor.root)
        {
            {
                self.stored_root = Some(root);
                self.stored_packet = Some(std::sync::Arc::new(raw));
                self.events.push(Event::Stored {
                    instance: self.instance,
                    root,
                });
                if self.descriptor.completion == CompletionMode::Storage {
                    self.broadcast(Kind::Ack(root));
                }
            }
        }
    }
    pub fn receive(&mut self, sender: Replica, msg: ProtMsg) {
        if sender >= self.membership.n() || msg.instance != self.instance {
            return;
        }
        match msg.kind {
            Kind::Init { index, bytes } if Some(sender) == self.instance.dealer => {
                if let Some(raw) = self.init.add(index, bytes) {
                    if self.descriptor.completion == CompletionMode::External
                        && self.descriptor.root.is_none()
                    {
                        self.unpinned_packet = Some(raw);
                    } else {
                        self.store_packet(raw);
                    }
                }
            }
            Kind::Ack(root) | Kind::Ready(root)
                if self.descriptor.completion == CompletionMode::Storage =>
            {
                if self.descriptor.root.is_some_and(|r| r != root) {
                    return;
                }
                // Determine the kind from the original message before insertion.
                let is_ack = matches!(msg.kind, Kind::Ack(_));
                let (slots, weights) = if is_ack {
                    (&mut self.acks, &mut self.ack_weights)
                } else {
                    (&mut self.readies, &mut self.ready_weights)
                };
                if let std::collections::hash_map::Entry::Vacant(e) = slots.entry(sender) {
                    e.insert(root);
                    *weights.entry(root).or_default() += &self.membership.weights[sender].0;
                }
            }
            Kind::Request(root) => {
                if self.descriptor.root.is_none_or(|r| r == root) {
                    self.requests.entry(sender).or_insert(root);
                }
            }
            Kind::Data { index, bytes } if self.asked && self.result.is_none() => {
                let mut stream = self.data_slots.remove(&sender).unwrap_or_else(|| {
                    super::stream::DataStream::new(self.codec.bundle_bytes(sender))
                });
                stream.add(index, bytes);
                self.accept_stream(sender, &mut stream);
                if self.result.is_none() {
                    self.data_slots.insert(sender, stream);
                }
            }
            _ => {}
        }
        self.advance();
    }
}
