//! Local work scheduling only. No clocks, retries, or protocol decisions.
use std::collections::VecDeque;

/// FIFO with at most one outstanding entry per dealer. A blocked dealer is
/// removed and is woken only by a new dependency event; it cannot spin or
/// repeatedly jump ahead of another ready dealer.
pub(super) struct DealerQueue {
    queue: VecDeque<usize>,
    queued: Vec<bool>,
}
impl DealerQueue {
    pub(super) fn new(n: usize) -> Self {
        Self {
            queue: VecDeque::new(),
            queued: vec![false; n],
        }
    }
    pub(super) fn wake(&mut self, dealer: usize) {
        if !self.queued[dealer] {
            self.queued[dealer] = true;
            self.queue.push_back(dealer);
        }
    }
    pub(super) fn pop(&mut self) -> Option<usize> {
        let dealer = self.queue.pop_front()?;
        self.queued[dealer] = false;
        Some(dealer)
    }
    pub(super) fn len(&self) -> usize {
        self.queue.len()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn duplicate_wakes_coalesce_and_requeued_work_cannot_starve_other_dealers() {
        let mut work = DealerQueue::new(4);
        work.wake(0);
        work.wake(3);
        for _ in 0..100 {
            work.wake(0);
        }
        assert_eq!(work.len(), 2);
        assert_eq!(work.pop(), Some(0));
        work.wake(0);
        work.wake(2);
        assert_eq!(work.pop(), Some(3));
        assert_eq!(work.pop(), Some(0));
        assert_eq!(work.pop(), Some(2));
        assert_eq!(work.pop(), None);
    }
}
