//! Bounded coalescing of ACKs whose frames are already accepted.
//! No timer or wait for a future frame. A Pending receive drains existing ACKs.
use crypto::hash::Hash;
use std::{
    future::{poll_fn, Future},
    io,
    pin::Pin,
    task::{ready, Context, Poll},
};
use tokio::io::AsyncWrite;

pub(super) const ACK_BATCH_FRAMES: usize = 16;
const ACK_BATCH_BYTES: usize = ACK_BATCH_FRAMES * std::mem::size_of::<Hash>();

pub(super) struct ReadyAcks<W> {
    writer: W,
    bytes: [u8; ACK_BATCH_BYTES],
    end: usize,
    written: usize,
}
impl<W: AsyncWrite + Unpin> ReadyAcks<W> {
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            bytes: [0; ACK_BATCH_BYTES],
            end: 0,
            written: 0,
        }
    }
    pub fn push(&mut self, ack: &Hash) {
        // No append after a partial write: wait_ready finishes that drain first.
        assert_eq!(self.written, 0);
        let end = self.end + ack.len();
        self.bytes[self.end..end].copy_from_slice(ack);
        self.end = end;
    }
    pub fn full(&self) -> bool {
        self.end == self.bytes.len()
    }
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.written < self.end {
            let n = ready!(
                Pin::new(&mut self.writer).poll_write(cx, &self.bytes[self.written..self.end])
            )?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "ACK write returned zero",
                )));
            }
            self.written += n;
        }
        self.end = 0;
        self.written = 0;
        Poll::Ready(Ok(()))
    }
    pub async fn drain(&mut self) -> io::Result<()> {
        poll_fn(|cx| self.poll_drain(cx)).await
    }
    pub async fn wait_ready<F: Future>(&mut self, future: F) -> io::Result<F::Output> {
        let mut future = std::pin::pin!(future);
        let mut draining = false;
        let mut received = None;
        poll_fn(|cx| {
            // Keep polling the ONE already-started receive while writes block:
            // an mpsc permit or sequence lock must be released when it can
            // complete. Its result is held until the preceding ACKs drain.
            // No additional receive is started and no ACK is appended meanwhile.
            if received.is_none() {
                match future.as_mut().poll(cx) {
                    Poll::Ready(result) => received = Some(result),
                    Poll::Pending => draining = true,
                }
            }
            if draining {
                ready!(self.poll_drain(cx))?;
                draining = false;
            }
            match received.take() {
                Some(result) => Poll::Ready(Ok(result)),
                None => Poll::Pending, // Receive registered a wakeup; keep it pinned.
            }
        })
        .await
    }
}

#[cfg(test)]
#[path = "weighted_ack_writer_tests.rs"]
mod tests;
