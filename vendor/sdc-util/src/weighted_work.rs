//! Bounded local scheduling; no clocks or protocol-level choices.
use std::collections::VecDeque;

/// Each dealer has at most one entry. At most three priority entries can
/// precede an already ready background entry, even under continuous wakeups.
/// Both queues are FIFO; blocked work is reinserted only on a dependency event.
pub struct RecoveryQueue {
    priority: Vec<bool>,
    queued: Vec<bool>,
    urgent: VecDeque<usize>,
    background: VecDeque<usize>,
    budget: usize,
}
const BURST: usize = 3;
impl RecoveryQueue {
    pub fn new(n: usize) -> Self {
        Self {
            priority: vec![false; n],
            queued: vec![false; n],
            urgent: VecDeque::new(),
            background: VecDeque::new(),
            budget: BURST,
        }
    }
    /// Called at Freeze using the local immutable coefficient vector.
    /// Pending work is retained and duplicates cannot appear.
    pub fn set_priorities(&mut self, priorities: &[bool]) {
        assert_eq!(priorities.len(), self.priority.len());
        self.priority.copy_from_slice(priorities);
        let pending = self
            .urgent
            .drain(..)
            .chain(self.background.drain(..))
            .collect::<Vec<_>>();
        for d in pending {
            if self.priority[d] {
                self.urgent.push_back(d);
            } else {
                self.background.push_back(d);
            }
        }
        self.budget = BURST;
    }
    pub fn wake(&mut self, d: usize) {
        if !self.queued[d] {
            self.queued[d] = true;
            if self.priority[d] {
                self.urgent.push_back(d);
            } else {
                self.background.push_back(d);
            }
        }
    }
    pub fn pop(&mut self) -> Option<usize> {
        let d = if !self.urgent.is_empty() && (self.background.is_empty() || self.budget > 0) {
            self.budget = self.budget.saturating_sub(1);
            self.urgent.pop_front()
        } else {
            self.budget = BURST;
            self.background.pop_front()
        }?;
        self.queued[d] = false;
        Some(d)
    }
    pub fn len(&self) -> usize {
        self.urgent.len() + self.background.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn freeze_reclassifies_pending_work_without_loss_or_duplicates() {
        let mut q = RecoveryQueue::new(6);
        for d in 0..6 {
            q.wake(d);
        }
        q.set_priorities(&[false, true, true, false, true, true]);
        for _ in 0..100 {
            q.wake(5);
        }
        assert_eq!(q.len(), 6);
        let order = std::iter::from_fn(|| q.pop()).collect::<Vec<_>>();
        assert_eq!(order, [1, 2, 4, 0, 5, 3]);
        assert!(q.is_empty());
    }
    #[test]
    fn repeated_priority_wakeups_cannot_starve_background_work() {
        let mut q = RecoveryQueue::new(5);
        q.set_priorities(&[true, true, false, false, false]);
        for d in 0..5 {
            q.wake(d);
        }
        let mut low = vec![];
        for step in 0..12 {
            let d = q.pop().unwrap();
            if d < 2 {
                for _ in 0..50 {
                    q.wake(d);
                }
            } else {
                low.push((step, d));
            }
            assert!(q.len() <= 5);
        }
        assert_eq!(low, [(3, 2), (7, 3), (11, 4)]);
    }
    #[test]
    fn either_queue_runs_without_waiting_for_the_other() {
        for priorities in [vec![true; 4], vec![false; 4]] {
            let mut q = RecoveryQueue::new(4);
            q.set_priorities(&priorities);
            for d in [3, 1, 0, 2] {
                q.wake(d);
            }
            assert_eq!(
                std::iter::from_fn(|| q.pop()).collect::<Vec<_>>(),
                [3, 1, 0, 2]
            );
            q.wake(2);
            assert_eq!(q.pop(), Some(2));
            assert!(q.is_empty());
        }
    }
}
