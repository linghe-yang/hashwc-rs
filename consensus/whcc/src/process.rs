//! Dispatch protocol actions to primitive channels and publish public events.
use crate::{Context, msg::Action};
use anyhow::Result;

impl Context {
    pub(crate) async fn flush(&mut self) -> Result<()> {
        for action in self.state.drain_actions() {
            match action {
                Action::Rbc(r) => self.rbc_tx.send(r).await?,
                Action::Ra(r) => self.ra_tx.send(r).await?,
                Action::Gather(r) => self.gather_tx.send(r).await?,
                Action::BinAa(r) => self.binaa_tx.send(r).await?,
                Action::Private { recipient, packet } => self.private.send(recipient, &packet)?,
                Action::Recovery { recipient, packet } => self.recovery.send(recipient, &packet)?,
            }
        }
        for event in self.state.drain_events() {
            // Event Debug contains public metadata and dyadic coefficients only.
            log::info!(
                "whcc party={} epoch={} event={event:?}",
                self.state.id,
                self.state.params.epoch
            );
            self.pending_events.push_back(event);
        }
        Ok(())
    }
}
