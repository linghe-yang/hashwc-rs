use super::State;
use sdc_util::observation::ServiceProgress;

impl State {
    /// Strict all-dealer predicate for an all-honest experiment. A silent/bad
    /// dealer may keep it false forever, without preventing the coin's output.
    pub fn service_progress(&self) -> ServiceProgress {
        let mut pending = std::collections::BTreeMap::new();
        pending.insert(
            "assignment_lists",
            (0..self.n)
                .filter(|&i| !self.assignments.delivered(i))
                .count(),
        );
        pending.insert(
            "sharing_completion",
            self.dealers.iter().filter(|d| !d.complete).count(),
        );
        pending.insert(
            "local_receipts",
            self.dealers.iter().filter(|d| d.receipt.is_none()).count(),
        );
        pending.insert(
            "local_storage",
            self.dealers
                .iter()
                .filter(|d| {
                    d.header
                        .as_ref()
                        .is_none_or(|h| d.stored_root != Some(h.root))
                })
                .count(),
        );
        pending.insert(
            "terminal_values",
            self.dealers.iter().filter(|d| d.value.is_none()).count(),
        );
        let mut tokens = 0;
        let mut retrievals = 0;
        let mut terminals = 0;
        for (d, state) in self.dealers.iter().enumerate() {
            tokens += (0..self.n)
                .filter(|&i| self.remote_authorized(i, d) && !state.served[i])
                .count();
            if self.assignments.authorized(self.id, d) {
                if self.remote_authorized(self.id, d) {
                    retrievals +=
                        usize::from(state.file.is_none() && state.storage_terminal.is_none());
                }
                terminals += usize::from(!state.terminal_sent);
            }
        }
        pending.insert("token_services", tokens);
        pending.insert("assigned_retrievals", retrievals);
        pending.insert("terminal_sends", terminals);
        pending.insert("application_actions", self.actions.len());
        pending.insert("scheduled_dealers", self.work.len());
        pending.insert("scheduled_recovery", self.recovery_work.len());
        pending.insert(
            "nonhonest_behavior",
            usize::from(self.behavior != crate::Behavior::Honest),
        );
        ServiceProgress::new(self.coin.is_some(), pending)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inspection_is_read_only_and_requires_late_receipts_after_output() {
        let node = super::super::tests::nodes(&[3; 4], 4, 20000).remove(0);
        let mut state = State::new(&node, crate::Parameters::default()).unwrap();
        let before = serde_json::to_value(state.service_progress()).unwrap();
        assert_eq!(
            before,
            serde_json::to_value(state.service_progress()).unwrap()
        );
        assert!(state.actions.is_empty() && state.events.is_empty());
        state.coin = Some(types::Coin::from_be_bytes(1, [0; 32]).unwrap());
        let progress = state.service_progress();
        assert!(progress.output_observed);
        assert_eq!(progress.pending["local_receipts"], 4);
        assert!(!progress.all_honest_services_complete);
    }
}
