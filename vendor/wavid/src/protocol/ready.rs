use crate::{CompletionMode, Event, Kind, State};
use anyhow::{ensure, Result};
use crypto::hash::Hash;
impl State {
    pub fn accept_completion(&mut self, root: Hash) -> Result<()> {
        ensure!(
            self.descriptor.completion == CompletionMode::External
                && self.descriptor.root == Some(root),
            "external completion must name the pinned root"
        );
        self.complete(root);
        self.advance();
        Ok(())
    }
    pub(crate) fn complete(&mut self, root: Hash) {
        if self.completed_root.is_none() {
            self.completed_root = Some(root);
            self.events.push(Event::Complete {
                instance: self.instance,
                root,
            });
        }
    }
    pub(crate) fn advance(&mut self) {
        if self.descriptor.completion == CompletionMode::Storage {
            if self.ready_root.is_none() {
                let candidates = self
                    .ack_weights
                    .iter()
                    .filter(|(_, w)| **w > self.membership.quorum)
                    .map(|(r, _)| *r)
                    .chain(
                        self.ready_weights
                            .iter()
                            .filter(|(_, w)| **w >= self.membership.threshold)
                            .map(|(r, _)| *r),
                    );
                if let Some(root) = candidates.min() {
                    self.ready_root = Some(root);
                    self.broadcast(Kind::Ready(root));
                }
            }
            if self.completed_root.is_none() {
                if let Some(root) = self
                    .ready_weights
                    .iter()
                    .filter(|(_, w)| **w > self.membership.quorum)
                    .map(|(r, _)| *r)
                    .min()
                {
                    self.complete(root);
                }
            }
        }
        self.advance_retrieval();
    }
}
