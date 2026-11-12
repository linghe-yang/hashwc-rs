//! Receiver-local work accounting. No timer, message batch or peer barrier.
use super::metrics;
use std::future::{poll_fn, Future};

// Zero disables the experimental policy; measurements still work when requested.
pub(super) const FRAME_BUDGET: usize = 0;
pub(super) const BYTE_BUDGET: usize = 0;

pub(super) struct ReceiveBudget<'a> {
    counts: &'a metrics::Counters,
    observe: bool,
    frame_limit: usize,
    byte_limit: usize,
    frames: usize,
    bytes: usize,
}
impl<'a> ReceiveBudget<'a> {
    pub fn new(counts: &'a metrics::Counters) -> Self {
        Self::with_limits(counts, metrics::io_enabled(), FRAME_BUDGET, BYTE_BUDGET)
    }
    pub fn with_limits(
        counts: &'a metrics::Counters,
        observe: bool,
        frame_limit: usize,
        byte_limit: usize,
    ) -> Self {
        Self {
            counts,
            observe,
            frame_limit,
            byte_limit,
            frames: 0,
            bytes: 0,
        }
    }
    fn active(&self) -> bool {
        self.observe || self.frame_limit != 0 || self.byte_limit != 0
    }
    fn reset(&mut self) {
        self.frames = 0;
        self.bytes = 0;
    }
    pub async fn track<F: Future>(&mut self, future: F) -> F::Output {
        if !self.active() {
            return future.await;
        }
        let mut future = std::pin::pin!(future);
        poll_fn(|cx| {
            let result = future.as_mut().poll(cx);
            if result.is_pending() {
                // Read, mutex, actor backpressure or ACK write already handed
                // control to the executor; do not add a redundant later yield.
                self.reset();
            }
            result
        })
        .await
    }
    /// Caller drains pending ACKs first when this predicts an explicit yield.
    pub fn yields_after(&self, bytes: usize) -> bool {
        (self.frame_limit != 0 && self.frames.saturating_add(1) >= self.frame_limit)
            || (self.byte_limit != 0 && self.bytes.saturating_add(bytes) >= self.byte_limit)
    }
    pub async fn complete(&mut self, bytes: usize) {
        if !self.active() {
            return;
        }
        self.frames += 1;
        self.bytes += bytes;
        if self.observe {
            self.counts.receive_complete(self.frames, self.bytes);
        }
        if (self.frame_limit != 0 && self.frames >= self.frame_limit)
            || (self.byte_limit != 0 && self.bytes >= self.byte_limit)
        {
            if self.observe {
                self.counts.receive_yield();
            }
            self.reset();
            // Caller drains accepted ACKs before an explicit yield.
            // yield_now self-wakes; it makes no promise about the next task.
            tokio::task::yield_now().await;
        }
    }
}

#[cfg(test)]
#[path = "weighted_budget_tests.rs"]
mod tests;
