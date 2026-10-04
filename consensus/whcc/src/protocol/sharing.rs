use crate::{
    msg::{Action, Event, PRIVATE_TOKEN},
    state::State,
};
use anyhow::Result;
use network::Packet;
use wiawvss::{PrivateShare, Public, ax};
impl State {
    pub fn rbc_event(&mut self, event: wrbc::Event) -> Result<()> {
        match event {
            wrbc::Event::Deliver { instance, data } if instance.epoch == self.params.epoch => {
                if let Some(d) = instance.dealer.filter(|&d| d < self.n) {
                    if instance.slot == 1 {
                        self.assignments.deliver(d, &data);
                    }
                    if instance.slot == 0
                        && self.dealers[d].public.is_none()
                        && !self.dealers[d].rejected_public
                    {
                        match Public::decode(&self.setup, &self.dealers[d].context, &data) {
                            Ok(public) => {
                                self.actions.push(Action::Ra(wra::Request::Register {
                                    instance,
                                    header_id: public.digest(),
                                }));
                                self.dealers[d].public = Some(public);
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
    pub fn private_packet(&mut self, sender: usize, packet: Packet) -> Result<()> {
        let d = packet.dealer;
        if sender >= self.n
            || d != sender
            || packet.epoch != self.params.epoch
            || packet.kind != PRIVATE_TOKEN
        {
            return Ok(());
        }
        let Ok(share) = PrivateShare::decode(&packet.payload) else {
            return Ok(());
        };
        if share.party != self.id
            || share.context_id != self.dealers[d].context.id()
            || share.setup_id != self.setup.id()
        {
            return Ok(());
        }
        if self.dealers[d].receipt.is_none() {
            self.dealers[d].pending_receipt = Some(share);
        }
        self.advance()
    }
    pub(super) fn receipts(&mut self) -> Result<()> {
        for d in 0..self.n {
            let dealer = &mut self.dealers[d];
            if let Some(public) = &dealer.public
                && let Some(share) = dealer.pending_receipt.take()
                && ax::verify_share(&self.setup, &dealer.context, public, &share)
                && dealer.receipt.is_none()
            {
                dealer.receipt = Some(share);
                self.actions.push(Action::Ra(wra::Request::Input {
                    instance: self.instance(d, 0),
                    value: true,
                }));
            }
        }
        Ok(())
    }
}
