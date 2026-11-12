use crate::{
    msg::{Action, Event, PRIVATE_TOKEN},
    state::State,
};
use anyhow::Result;
use network::Packet;
use wiawvss::{
    IncrementalRecovery,
    certified::{self, Certificate, Evidence, Header, Receipt},
};
impl State {
    pub fn short_broadcast_event(&mut self, event: crate::root_rbc::ServiceEvent) -> Result<()> {
        match event {
            crate::root_rbc::ServiceEvent::Root(e) => self.root_event(e),
            crate::root_rbc::ServiceEvent::List(e) => self.list_event(e),
        }
    }
    pub fn list_event(&mut self, event: crate::root_rbc::chunks::Event) -> Result<()> {
        if self.params.list_broadcast == super::parameters::ListBroadcast::FixedChunksV1
            && event.instance.epoch == self.params.epoch
            && event.instance.slot == 1
            && let Some(party) = event.instance.dealer.filter(|&d| d < self.n)
        {
            self.install_assignments(party, &event.data);
        }
        self.advance()
    }

    /// Called only for authenticated RBC delivery. Even an invalid delivered
    /// list resolves waiting terminal authorization (to false).
    pub(super) fn install_assignments(&mut self, party: usize, data: &[u8]) {
        if self.group_plan.is_some() || self.assignments.delivered(party) {
            return;
        }
        let valid = match self.params.list_broadcast {
            super::parameters::ListBroadcast::FixedChunksV1 => {
                self.assignments.deliver_ranked(party, data)
            }
            super::parameters::ListBroadcast::CodedV1 => self.assignments.deliver(party, data),
        };
        if valid {
            for d in self.assignments.lists[party].as_ref().unwrap().clone() {
                if party == self.id { sdc_util::observation::bulk_audit::add(d, "selected", 1); }
                if self.remote_authorized(party, d) {
                    self.actions.push(Action::Avid(wavid::Request::Authorize {
                        instance: self.instance(d, 0),
                        retrievers: vec![party],
                    }));
                    if !self.dealers[d].served[party] {
                        self.dealers[d].pending_recipients.insert(party);
                    }
                }
                // A self edge still authorizes a terminal after Complete/Freeze.
                self.work.wake(d);
            }
        }
        // A terminal can refer to a dealer omitted from the newly delivered
        // list. Wake that dealer too, to retire the unauthorized buffered slot.
        for d in std::mem::take(&mut self.terminal_waiters[party]) {
            self.dealers[d].ready_terminals.insert(party);
            self.work.wake(d);
        }
    }
    /// Root delivery reconstructs the same canonical Header; no header encoding,
    /// source proof or arbitrary payload is needed on the Bracha path.
    pub fn root_event(&mut self, event: crate::root_rbc::Event) -> Result<()> {
        let instance = event.instance;
        if self.params.short_root_rbc
            && instance.epoch == self.params.epoch
            && instance.slot == 0
            && let Some(d) = instance.dealer.filter(|&d| d < self.n)
            && self.dealers[d].header.is_none()
            && !self.dealers[d].rejected_public
        {
            let header = Header::new(&self.setup, &self.dealers[d].context, event.root);
            self.install_header(d, header);
        }
        self.advance()
    }
    fn install_header(&mut self, d: usize, header: Header) {
        let instance = self.instance(d, 0);
        self.actions.push(Action::Avid(wavid::Request::Pin {
            instance,
            root: header.root,
        }));
        self.actions.push(Action::Ra(wra::Request::Register {
            instance,
            header_id: header.id(),
        }));
        self.dealers[d].header = Some(header);
        self.work.wake(d);
    }
    pub fn rbc_event(&mut self, event: wrbc::Event) -> Result<()> {
        match event {
            wrbc::Event::Deliver { instance, data } if instance.epoch == self.params.epoch => {
                if let Some(d) = instance.dealer.filter(|&d| d < self.n) {
                    if instance.slot == 1
                        && self.params.list_broadcast == super::parameters::ListBroadcast::CodedV1
                    {
                        self.install_assignments(d, &data);
                    }
                    if instance.slot == 0
                        && !self.params.short_root_rbc
                        && self.dealers[d].header.is_none()
                        && !self.dealers[d].rejected_public
                    {
                        match Header::decode(&self.setup, &self.dealers[d].context, &data) {
                            Ok(header) => self.install_header(d, header),
                            Err(_) => self.dealers[d].rejected_public = true,
                        }
                    }
                }
            }
            wrbc::Event::Invalid { instance, .. }
                if !self.params.short_root_rbc
                    && instance.epoch == self.params.epoch
                    && instance.slot == 0 =>
            {
                if let Some(d) = instance.dealer.filter(|&d| d < self.n) {
                    self.dealers[d].rejected_public = true;
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
            } if instance.epoch == self.params.epoch && instance.slot == 0 => {
                if let Some(d) = instance.dealer.filter(|&d| d < self.n)
                    && let Some(header) = &self.dealers[d].header
                    && !self.dealers[d].complete
                {
                    // Global sharing completion need not imply THIS party holds data.
                    self.actions.push(Action::Avid(wavid::Request::Complete {
                        instance,
                        root: header.root,
                    }));
                    self.dealers[d].complete = true;
                    self.work.wake(d);
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
    pub fn avid_event(&mut self, event: wavid::Event) -> Result<()> {
        let bits = self.contribution_bits();
        match event {
            wavid::Event::Stored { instance, root }
                if instance.epoch == self.params.epoch && instance.slot == 0 =>
            {
                if let Some(d) = instance.dealer.filter(|&d| d < self.n)
                    && self.dealers[d]
                        .header
                        .as_ref()
                        .is_some_and(|h| h.root == root)
                    && self.dealers[d].stored_root != Some(root)
                {
                    self.dealers[d].stored_root = Some(root);
                    self.work.wake(d);
                }
            }
            wavid::Event::Result { instance, result }
                if instance.epoch == self.params.epoch && instance.slot == 0 =>
            {
                if let Some(d) = instance.dealer.filter(|&d| d < self.n)
                    && self.remote_authorized(self.id, d)
                {
                    let dealer = &mut self.dealers[d];
                    if let Some(header) = &dealer.header {
                        match result {
                            wavid::Retrieval::Invalid(fault) => {
                                let cert = Certificate {
                                    header_id: header.id(),
                                    evidence: Evidence::Storage(fault),
                                };
                                anyhow::ensure!(
                                    certified::verify(
                                        &self.setup,
                                        &dealer.context,
                                        &dealer.codec,
                                        header,
                                        &cert,
                                        bits
                                    ),
                                    "invalid local storage proof"
                                );
                                dealer.storage_terminal = Some(cert);
                            }
                            wavid::Retrieval::File(raw) => {
                                anyhow::ensure!(
                                    raw.root() == header.root
                                        && raw.coding_context() == dealer.codec.context
                                        && raw.parameters() == dealer.codec.parameters(),
                                    "WAVID result root mismatch"
                                );
                                if dealer.value.is_none() {
                                    match IncrementalRecovery::new(
                                        &self.setup,
                                        &dealer.context,
                                        raw.clone(),
                                    ) {
                                        Ok(cache) => dealer.recovery_cache = Some(cache),
                                        Err(_) => {
                                            dealer.storage_terminal = Some(Certificate {
                                                header_id: header.id(),
                                                evidence: Evidence::Format(certified::openings(
                                                    &dealer.codec,
                                                    &raw,
                                                    &[(0, 72)],
                                                )?),
                                            })
                                        }
                                    }
                                }
                                if dealer.file.is_none() { sdc_util::observation::bulk_audit::add(d, "remote_file_bytes", raw.as_ref().len()); }
                                dealer.file = Some(raw);
                            }
                        }
                        dealer.recovery_dirty = dealer.value.is_none();
                        self.work.wake(d);
                    }
                }
            }
            wavid::Event::Rejected { reason, .. } => anyhow::bail!("WAVID: {reason}"),
            _ => {}
        }
        self.advance()
    }
    pub fn contribution_bits(&self) -> usize {
        (self.params.output_bits + self.params.rounding_bits + 1) as usize
    }
    pub fn private_packet(&mut self, sender: usize, packet: Packet) -> Result<()> {
        let d = packet.dealer;
        if sender >= self.n
            || sender != d
            || packet.epoch != self.params.epoch
            || packet.kind != PRIVATE_TOKEN
        {
            return Ok(());
        }
        if let Ok(receipt) = Receipt::decode(&self.dealers[d].codec, &packet.payload)
            && self.dealers[d].receipt.is_none()
            && self.dealers[d].pending_receipt.is_none()
        {
            self.dealers[d].pending_receipt = Some(receipt);
            self.work.wake(d);
        }
        self.advance()
    }
    pub(super) fn receipts(&mut self, d: usize) -> Result<()> {
        let remote = self.remote_authorized(self.id, d);
        let dealer = &mut self.dealers[d];
        if let Some(header) = &dealer.header {
            if let Some(raw) = dealer.pending_receipt.take()
                && dealer.receipt.is_none()
            {
                dealer.receipt =
                    raw.verify(&self.setup, &dealer.context, &dealer.codec, header, self.id);
            }
            // One ECHO for the conjunction, never for a header or fragment receipt alone.
            if dealer.receipt.is_some() && dealer.stored_root == Some(header.root) && !dealer.echoed
            {
                dealer.echoed = true;
                self.actions.push(Action::Ra(wra::Request::Input {
                    instance: sdc_types::InstanceId::new(self.params.epoch, Some(d), 0),
                    value: true,
                }));
            }
            // Public bulk retrieval may precede freeze, private tokens may not.
            if remote && !dealer.retrieving {
                if self.params.reuse_verified_material {
                    let material = wavid::VerifiedMaterial::new(dealer.codec.clone(), header.root);
                    self.actions
                        .push(Action::Avid(wavid::Request::AttachMaterial {
                            instance: sdc_types::InstanceId::new(self.params.epoch, Some(d), 0),
                            material: material.clone(),
                        }));
                    dealer.material = Some(material);
                }
                sdc_util::observation::bulk_audit::add(d, "retrieve_started", 1);
                dealer.retrieving = true;
                self.actions.push(Action::Avid(wavid::Request::Retrieve {
                    instance: sdc_types::InstanceId::new(self.params.epoch, Some(d), 0),
                }));
            }
        }
        Ok(())
    }
}
