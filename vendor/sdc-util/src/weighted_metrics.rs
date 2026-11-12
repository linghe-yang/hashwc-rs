//! Socket payload accounting. Atomics do not change framing, scheduling or ACKs.
use serde::Serialize;
use std::{
    collections::BTreeMap,
    io::{self, IoSlice},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex, OnceLock,
    },
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Default)]
pub struct Counters {
    sent: AtomicU64,
    received: AtomicU64,
    queued: AtomicU64,
    acknowledged: AtomicU64,
    logical_frames: AtomicU64,
    logical_frame_bytes: AtomicU64,
    connected_streams: AtomicU64,
    replayed_frames: AtomicU64,
    stall_reconnects: AtomicU64,
    io_disconnects: AtomicU64,
    invalid_acks: AtomicU64,
    connect_failures: AtomicU64,
    receive_backpressure_waits: AtomicU64,
    receive_backpressure_ns: AtomicU64,
    io_observed: AtomicBool,
    io_read_polls: AtomicU64,
    io_read_successes: AtomicU64,
    io_read_pending: AtomicU64,
    io_write_polls: AtomicU64,
    io_write_successes: AtomicU64,
    io_write_pending: AtomicU64,
    ack_read_polls: AtomicU64,
    ack_read_successes: AtomicU64,
    ack_read_pending: AtomicU64,
    ack_received_bytes: AtomicU64,
    ack_write_polls: AtomicU64,
    ack_write_successes: AtomicU64,
    ack_write_pending: AtomicU64,
    ack_sent_bytes: AtomicU64,
    receive_frames: AtomicU64,
    receive_turns: AtomicU64,
    receive_max_frames_per_turn: AtomicU64,
    receive_max_bytes_per_turn: AtomicU64,
    receive_budget_yields: AtomicU64,
}
#[derive(Serialize, Default)]
pub struct Snapshot {
    pub sent_bytes: u64,
    pub received_bytes: u64,
    pub queued_frames: u64,
    pub acknowledged_frames: u64,
    /// Each remote serialized frame once, including its wire framing and MAC.
    /// Excludes ACKs; a fully acknowledged run owes one 32-byte ACK per frame.
    pub logical_frames: u64,
    pub logical_frame_bytes: u64,
    pub connected_streams: u64,
    /// Pending frames with at least one byte previously written, reset on reconnect.
    pub replayed_frames: u64,
    pub stall_reconnects: u64,
    pub io_disconnects: u64,
    pub invalid_acks: u64,
    pub connect_failures: u64,
    pub receive_backpressure_waits: u64,
    pub receive_backpressure_ns: u64,
    /// Opt-in observations at AsyncRead/AsyncWrite, NOT kernel syscall counts.
    pub io_observed: bool,
    pub io_read_polls: u64,
    /// Ready(Ok) reads that returned at least one byte; excludes EOF.
    pub io_read_successes: u64,
    pub io_read_pending: u64,
    pub io_write_polls: u64,
    /// Ready(Ok) writes that accepted at least one byte.
    pub io_write_successes: u64,
    pub io_write_pending: u64,
    // ACK-only reads are a subset of io_read_*; receiver turns end at any Pending.
    pub ack_read_polls: u64,
    pub ack_read_successes: u64,
    pub ack_read_pending: u64,
    pub ack_received_bytes: u64,
    pub ack_write_polls: u64,
    pub ack_write_successes: u64,
    pub ack_write_pending: u64,
    pub ack_sent_bytes: u64,
    /// Accepted frames, including authenticated replays; ACKs may still be queued.
    pub receive_frames: u64,
    pub receive_turns: u64,
    pub receive_max_frames_per_turn: u64,
    pub receive_max_bytes_per_turn: u64,
    pub receive_budget_yields: u64,
}
static REGISTRY: OnceLock<Mutex<BTreeMap<String, Arc<Counters>>>> = OnceLock::new();
pub(super) fn counter(component: &str) -> Arc<Counters> {
    REGISTRY
        .get_or_init(Default::default)
        .lock()
        .unwrap()
        .entry(component.into())
        .or_default()
        .clone()
}
pub fn snapshot() -> BTreeMap<String, Snapshot> {
    REGISTRY
        .get_or_init(Default::default)
        .lock()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), v.current()))
        .collect()
}
impl Counters {
    pub(super) fn current(&self) -> Snapshot {
        Snapshot {
            sent_bytes: self.sent.load(Ordering::Relaxed),
            received_bytes: self.received.load(Ordering::Relaxed),
            queued_frames: self.queued.load(Ordering::Relaxed),
            acknowledged_frames: self.acknowledged.load(Ordering::Relaxed),
            logical_frames: self.logical_frames.load(Ordering::Relaxed),
            logical_frame_bytes: self.logical_frame_bytes.load(Ordering::Relaxed),
            connected_streams: self.connected_streams.load(Ordering::Relaxed),
            replayed_frames: self.replayed_frames.load(Ordering::Relaxed),
            stall_reconnects: self.stall_reconnects.load(Ordering::Relaxed),
            io_disconnects: self.io_disconnects.load(Ordering::Relaxed),
            invalid_acks: self.invalid_acks.load(Ordering::Relaxed),
            connect_failures: self.connect_failures.load(Ordering::Relaxed),
            receive_backpressure_waits: self.receive_backpressure_waits.load(Ordering::Relaxed),
            receive_backpressure_ns: self.receive_backpressure_ns.load(Ordering::Relaxed),
            io_observed: self.io_observed.load(Ordering::Relaxed),
            io_read_polls: self.io_read_polls.load(Ordering::Relaxed),
            io_read_successes: self.io_read_successes.load(Ordering::Relaxed),
            io_read_pending: self.io_read_pending.load(Ordering::Relaxed),
            io_write_polls: self.io_write_polls.load(Ordering::Relaxed),
            io_write_successes: self.io_write_successes.load(Ordering::Relaxed),
            io_write_pending: self.io_write_pending.load(Ordering::Relaxed),
            ack_read_polls: self.ack_read_polls.load(Ordering::Relaxed),
            ack_read_successes: self.ack_read_successes.load(Ordering::Relaxed),
            ack_read_pending: self.ack_read_pending.load(Ordering::Relaxed),
            ack_received_bytes: self.ack_received_bytes.load(Ordering::Relaxed),
            ack_write_polls: self.ack_write_polls.load(Ordering::Relaxed),
            ack_write_successes: self.ack_write_successes.load(Ordering::Relaxed),
            ack_write_pending: self.ack_write_pending.load(Ordering::Relaxed),
            ack_sent_bytes: self.ack_sent_bytes.load(Ordering::Relaxed),
            receive_frames: self.receive_frames.load(Ordering::Relaxed),
            receive_turns: self.receive_turns.load(Ordering::Relaxed),
            receive_max_frames_per_turn: self.receive_max_frames_per_turn.load(Ordering::Relaxed),
            receive_max_bytes_per_turn: self.receive_max_bytes_per_turn.load(Ordering::Relaxed),
            receive_budget_yields: self.receive_budget_yields.load(Ordering::Relaxed),
        }
    }
    pub(super) fn receive_complete(&self, frames: usize, bytes: usize) {
        self.receive_frames.fetch_add(1, Ordering::Relaxed);
        if frames == 1 {
            self.receive_turns.fetch_add(1, Ordering::Relaxed);
        }
        self.receive_max_frames_per_turn
            .fetch_max(frames as u64, Ordering::Relaxed);
        self.receive_max_bytes_per_turn
            .fetch_max(bytes as u64, Ordering::Relaxed);
    }
    pub(super) fn receive_yield(&self) {
        self.receive_budget_yields.fetch_add(1, Ordering::Relaxed);
    }
    pub(super) fn encoded(&self, bytes: usize) {
        self.logical_frames.fetch_add(1, Ordering::Relaxed);
        self.logical_frame_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }
    pub(super) fn connected(&self) {
        self.connected_streams.fetch_add(1, Ordering::Relaxed);
    }
    pub(super) fn stall_reconnect(&self) {
        self.stall_reconnects.fetch_add(1, Ordering::Relaxed);
    }
    pub(super) fn io_disconnect(&self) {
        self.io_disconnects.fetch_add(1, Ordering::Relaxed);
    }
    pub(super) fn invalid_ack(&self) {
        self.invalid_acks.fetch_add(1, Ordering::Relaxed);
    }
    pub(super) fn connect_failure(&self) {
        self.connect_failures.fetch_add(1, Ordering::Relaxed);
    }
    pub(super) fn backpressure(&self, elapsed: std::time::Duration) {
        self.receive_backpressure_waits
            .fetch_add(1, Ordering::Relaxed);
        self.receive_backpressure_ns.fetch_add(
            elapsed.as_nanos().min(u64::MAX as u128) as u64,
            Ordering::Relaxed,
        );
    }
    pub(super) fn replay(&self) {
        self.replayed_frames.fetch_add(1, Ordering::Relaxed);
    }
    pub(super) fn queue(&self) {
        self.queued.fetch_add(1, Ordering::Relaxed);
    }
    pub(super) fn unqueue(&self) {
        self.queued.fetch_sub(1, Ordering::Relaxed);
    }
    pub(super) fn acknowledge(&self) {
        self.acknowledged.fetch_add(1, Ordering::Relaxed);
    }
}
pub(super) fn io_enabled() -> bool {
    static IO_ENABLED: OnceLock<bool> = OnceLock::new();
    *IO_ENABLED.get_or_init(|| {
        crate::profile::enabled() || std::env::var("COIN_IO_METRICS").is_ok_and(|v| v == "1")
    })
}
pub(super) struct Counted<T> {
    inner: T,
    counts: Arc<Counters>,
    observe_io: bool,
    ack_reader: bool,
    ack_writer: bool,
}
impl<T> Counted<T> {
    pub(super) fn new(inner: T, counts: Arc<Counters>) -> Self {
        let observe_io = io_enabled();
        Self::with_observations(inner, counts, observe_io)
    }
    pub(super) fn ack_reader(inner: T, counts: Arc<Counters>) -> Self {
        let mut reader = Self::new(inner, counts);
        reader.ack_reader = true;
        reader
    }
    pub(super) fn ack_writer(inner: T, counts: Arc<Counters>) -> Self {
        let mut writer = Self::new(inner, counts);
        writer.ack_writer = true;
        writer
    }
    fn observe_ack_write(&self, result: &Poll<io::Result<usize>>) {
        if !self.ack_writer {
            return;
        }
        self.counts.ack_write_polls.fetch_add(1, Ordering::Relaxed);
        match result {
            Poll::Pending => {
                self.counts
                    .ack_write_pending
                    .fetch_add(1, Ordering::Relaxed);
            }
            Poll::Ready(Ok(n)) if *n > 0 => {
                self.counts
                    .ack_write_successes
                    .fetch_add(1, Ordering::Relaxed);
                self.counts
                    .ack_sent_bytes
                    .fetch_add(*n as u64, Ordering::Relaxed);
            }
            _ => {}
        }
    }
    pub(super) fn with_observations(inner: T, counts: Arc<Counters>, observe_io: bool) -> Self {
        if observe_io {
            counts.io_observed.store(true, Ordering::Relaxed);
        }
        Self {
            inner,
            counts,
            observe_io,
            ack_reader: false,
            ack_writer: false,
        }
    }
}
impl<T: AsyncRead + Unpin> AsyncRead for Counted<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        let bytes = buf.filled().len() - before;
        this.counts
            .received
            .fetch_add(bytes as u64, Ordering::Relaxed);
        if this.observe_io {
            if this.ack_reader {
                this.counts.ack_read_polls.fetch_add(1, Ordering::Relaxed);
                this.counts
                    .ack_received_bytes
                    .fetch_add(bytes as u64, Ordering::Relaxed);
                match &result {
                    Poll::Pending => {
                        this.counts.ack_read_pending.fetch_add(1, Ordering::Relaxed);
                    }
                    Poll::Ready(Ok(())) if bytes > 0 => {
                        this.counts
                            .ack_read_successes
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    _ => {}
                }
            }
            this.counts.io_read_polls.fetch_add(1, Ordering::Relaxed);
            match &result {
                Poll::Pending => {
                    this.counts.io_read_pending.fetch_add(1, Ordering::Relaxed);
                }
                Poll::Ready(Ok(())) if bytes > 0 => {
                    this.counts
                        .io_read_successes
                        .fetch_add(1, Ordering::Relaxed);
                }
                _ => {}
            }
        }
        result
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for Counted<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = result {
            this.counts.sent.fetch_add(n as u64, Ordering::Relaxed);
        }
        if this.observe_io {
            this.observe_ack_write(&result);
            this.counts.io_write_polls.fetch_add(1, Ordering::Relaxed);
            match &result {
                Poll::Pending => {
                    this.counts.io_write_pending.fetch_add(1, Ordering::Relaxed);
                }
                Poll::Ready(Ok(n)) if *n > 0 => {
                    this.counts
                        .io_write_successes
                        .fetch_add(1, Ordering::Relaxed);
                }
                _ => {}
            }
        }
        result
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write_vectored(cx, bufs);
        if let Poll::Ready(Ok(n)) = result {
            this.counts.sent.fetch_add(n as u64, Ordering::Relaxed);
        }
        if this.observe_io {
            this.observe_ack_write(&result);
            this.counts.io_write_polls.fetch_add(1, Ordering::Relaxed);
            match &result {
                Poll::Pending => {
                    this.counts.io_write_pending.fetch_add(1, Ordering::Relaxed);
                }
                Poll::Ready(Ok(n)) if *n > 0 => {
                    this.counts
                        .io_write_successes
                        .fetch_add(1, Ordering::Relaxed);
                }
                _ => {}
            }
        }
        result
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[tokio::test]
    async fn counts_partial_reads_writes_and_ack_both_directions() {
        let (a, b) = tokio::io::duplex(17);
        let ca = Arc::new(Counters::default());
        let cb = Arc::new(Counters::default());
        let mut a = Counted::with_observations(a, ca.clone(), true);
        a.ack_reader = true;
        a.ack_writer = true;
        let mut b = Counted::with_observations(b, cb.clone(), false);
        let send = tokio::spawn(async move {
            a.write_all(&[7; 4096]).await.unwrap();
            let mut ack = [0; 32];
            a.read_exact(&mut ack).await.unwrap();
            assert_eq!(ack, [9; 32]);
        });
        let mut data = [0; 4096];
        b.read_exact(&mut data).await.unwrap();
        assert_eq!(data, [7; 4096]);
        b.write_all(&[9; 32]).await.unwrap();
        send.await.unwrap();
        assert_eq!(ca.sent.load(Ordering::Relaxed), 4096);
        assert_eq!(ca.received.load(Ordering::Relaxed), 32);
        assert_eq!(cb.sent.load(Ordering::Relaxed), 32);
        assert_eq!(cb.received.load(Ordering::Relaxed), 4096);
        let observed = ca.current();
        assert!(observed.io_observed);
        assert_eq!(observed.ack_received_bytes, 32);
        assert_eq!(observed.ack_sent_bytes, 4096);
        assert_eq!(observed.ack_write_polls, observed.io_write_polls);
        assert_eq!(observed.ack_write_successes, observed.io_write_successes);
        assert_eq!(observed.ack_write_pending, observed.io_write_pending);
        assert_eq!(observed.ack_read_polls, observed.io_read_polls);
        assert_eq!(observed.ack_read_successes, observed.io_read_successes);
        assert_eq!(observed.ack_read_pending, observed.io_read_pending);
        assert!(observed.io_write_successes > 0);
        assert!(observed.io_read_successes > 0);
        assert!(observed.io_write_polls >= observed.io_write_successes + observed.io_write_pending);
        assert!(observed.io_read_polls >= observed.io_read_successes + observed.io_read_pending);
        let disabled = cb.current();
        assert!(!disabled.io_observed);
        assert_eq!(disabled.io_read_polls, 0);
        assert_eq!(disabled.ack_read_polls, 0);
        assert_eq!(disabled.ack_write_polls, 0);
        assert_eq!(disabled.io_write_polls, 0);
    }
}
