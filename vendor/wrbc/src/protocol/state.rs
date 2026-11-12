use crate::{Event, ProtMsg};
use anyhow::{Result, ensure};
use crypto::hash::Hash;
use types::{InstanceId, SendAction, WeightedMembership};
/// WRBC uses one WAVID storage quorum; receivers retrieve its canonical file.
pub struct State {
    pub storage: wavid::State,
    pub delivered: Option<wavid::ValidatedFile>,
    pub rejected: bool,
    pub outgoing: Vec<SendAction<ProtMsg>>,
    pub events: Vec<Event>,
    reuse_local_dealer: bool,
    // Only broadcast's canonical encoder can populate this slot. Network data
    // and an application-supplied ValidatedFile have no setter for it.
    local_file: Option<wavid::ValidatedFile>,
    local_broadcast: bool,
}
impl State {
    pub fn new(
        membership: WeightedMembership,
        id: usize,
        instance: InstanceId,
        public_id: Hash,
        file_bytes: usize,
    ) -> Result<Self> {
        Self::with_params(
            membership,
            id,
            instance,
            public_id,
            file_bytes,
            Default::default(),
        )
    }
    /// Select the same public coding parameters at all parties (see WAVID CodingParams).
    pub fn with_params(
        membership: WeightedMembership,
        id: usize,
        instance: InstanceId,
        public_id: Hash,
        file_bytes: usize,
        coding: wavid::CodingParams,
    ) -> Result<Self> {
        Self::with_params_and_local_reuse(
            membership, id, instance, public_id, file_bytes, coding, false,
        )
    }
    /// Opt-in dealer file reuse. The dealer waits for the identical storage
    /// quorum/root as all receivers; every peer's storage service remains live.
    pub fn with_params_and_local_reuse(
        membership: WeightedMembership,
        id: usize,
        instance: InstanceId,
        public_id: Hash,
        file_bytes: usize,
        coding: wavid::CodingParams,
        reuse_local_dealer: bool,
    ) -> Result<Self> {
        let reuse_local_dealer = reuse_local_dealer && instance.dealer == Some(id);
        let retrievers = (0..membership.n()).collect();
        let mut storage = wavid::State::new(
            membership,
            id,
            instance,
            public_id,
            wavid::Descriptor {
                coding,
                file_bytes,
                root: None,
                retrievers,
                completion: wavid::CompletionMode::Storage,
            },
        )?;
        // Defer the local result until broadcast has supplied its canonical
        // file, even if READY messages complete the instance before Start.
        if !reuse_local_dealer {
            storage.retrieve()?;
        }
        Ok(Self {
            storage,
            delivered: None,
            rejected: false,
            outgoing: vec![],
            events: vec![],
            reuse_local_dealer,
            local_file: None,
            local_broadcast: false,
        })
    }
    pub fn broadcast(&mut self, data: &[u8]) -> Result<()> {
        if self.reuse_local_dealer {
            ensure!(!self.local_broadcast, "only dealer may disperse, once");
            let prepared = self
                .storage
                .codec
                .prepare_dispersal(data.to_vec(), &Default::default())?;
            self.storage.disperse_cached(prepared.clone())?;
            self.local_broadcast = true;
            self.local_file = Some(prepared.file().clone());
        } else {
            self.storage.disperse(data)?;
        }
        self.collect();
        Ok(())
    }
    pub fn receive(&mut self, sender: usize, msg: ProtMsg) {
        self.storage.receive(sender, msg);
        self.collect();
    }
    fn collect(&mut self) {
        if self.delivered.is_none() && !self.rejected {
            if let Some(file) = &self.local_file {
                if self.storage.completed_root == Some(file.root())
                    && file.coding_context() == self.storage.codec.context
                    && file.parameters() == self.storage.codec.parameters()
                    && file.len() == self.storage.codec.file_bytes
                {
                    let data = self.local_file.take().expect("checked local file");
                    self.delivered = Some(data.clone());
                    self.events.push(Event::Deliver {
                        instance: self.storage.instance,
                        data,
                    });
                }
            }
        }
        // Output never stops storage ACK/READY handling or late peer responses.
        self.outgoing
            .extend(std::mem::take(&mut self.storage.outgoing));
        for event in std::mem::take(&mut self.storage.events) {
            if let wavid::Event::Result { instance, result } = event {
                match result {
                    wavid::Retrieval::File(data) => {
                        if self.delivered.is_none() && !self.rejected {
                            self.delivered = Some(data.clone());
                            self.events.push(Event::Deliver { instance, data });
                        }
                    }
                    wavid::Retrieval::Invalid(proof) => {
                        if self.delivered.is_none() && !self.rejected {
                            self.rejected = true;
                            self.events.push(Event::Invalid { instance, proof });
                        }
                    }
                }
            }
        }
    }
}
