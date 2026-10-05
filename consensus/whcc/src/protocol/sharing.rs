use crate::{
    msg::{Action, Event, PRIVATE_TOKEN},
    state::State,
};
use anyhow::Result;
use network::Packet;
use wiawvss::{
    Public,
    certified::{self, Certificate, Evidence, Header, Receipt},
};
impl State {
    pub fn rbc_event(&mut self, event: wrbc::Event) -> Result<()> {
        match event {
            wrbc::Event::Deliver { instance, data } if instance.epoch == self.params.epoch => {
                if let Some(d) = instance.dealer.filter(|&d| d < self.n) {
                    if instance.slot == 1 && self.assignments.deliver(d, &data) {
                        for dealer in self.assignments.lists[d].as_ref().unwrap().clone() {
                            self.actions.push(Action::Avid(wavid::Request::Authorize {
                                instance: self.instance(dealer, 0),
                                retrievers: vec![d],
                            }));
                        }
                    }
                    if instance.slot == 0
                        && self.dealers[d].header.is_none()
                        && !self.dealers[d].rejected_public
                    {
                        match Header::decode(&self.setup, &self.dealers[d].context, &data) {
                            Ok(header) => {
                                self.actions.push(Action::Avid(wavid::Request::Pin {
                                    instance,
                                    root: header.root,
                                }));
                                self.actions.push(Action::Ra(wra::Request::Register {
                                    instance,
                                    header_id: header.id(),
                                }));
                                self.dealers[d].header = Some(header);
                            }
                            Err(_) => self.dealers[d].rejected_public = true,
                        }
                    }
                }
            }
            wrbc::Event::Invalid { instance, .. }
                if instance.epoch == self.params.epoch && instance.slot == 0 =>
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
                {
                    self.dealers[d].stored_root = Some(root);
                }
            }
            wavid::Event::Result { instance, result }
                if instance.epoch == self.params.epoch && instance.slot == 0 =>
            {
                if let Some(d) = instance.dealer.filter(|&d| d < self.n)
                    && self.assignments.authorized(self.id, d)
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
                                match Public::decode(&self.setup, &dealer.context, &raw) {
                                    Ok(public) => dealer.public = Some(public),
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
                                dealer.file = Some(raw);
                            }
                        }
                        dealer.recovery_dirty = true;
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
        }
        self.advance()
    }
    pub(super) fn receipts(&mut self) -> Result<()> {
        for d in 0..self.n {
            let dealer = &mut self.dealers[d];
            if let Some(header) = &dealer.header {
                if let Some(raw) = dealer.pending_receipt.take()
                    && dealer.receipt.is_none()
                {
                    dealer.receipt =
                        raw.verify(&self.setup, &dealer.context, &dealer.codec, header, self.id);
                }
                // One ECHO for the conjunction, never for a header or fragment receipt alone.
                if dealer.receipt.is_some()
                    && dealer.stored_root == Some(header.root)
                    && !dealer.echoed
                {
                    dealer.echoed = true;
                    self.actions.push(Action::Ra(wra::Request::Input {
                        instance: sdc_types::InstanceId::new(self.params.epoch, Some(d), 0),
                        value: true,
                    }));
                }
                // Public bulk retrieval may precede freeze, private tokens may not.
                if self.assignments.authorized(self.id, d) && !dealer.retrieving {
                    dealer.retrieving = true;
                    self.actions.push(Action::Avid(wavid::Request::Retrieve {
                        instance: sdc_types::InstanceId::new(self.params.epoch, Some(d), 0),
                    }));
                }
            }
        }
        Ok(())
    }
}
