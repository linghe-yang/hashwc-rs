# Measurement-only transport overlay

Source: `https://github.com/linghe-yang/Secure-Distributed-Computing-Protocols.git`,
revision `731e0b81166125ea756c5a047ab813ccb8af7111`, crate `util`.

This local patch adds `weighted::metrics::snapshot()` and atomic socket byte,
queued-message, and acknowledged-message counters. Counted AsyncRead/AsyncWrite
wrappers delegate the same read/write/vectored-write operations to the original
socket. They include partial writes and replayed bytes. The sender/receiver
algorithms, frames, keys, MACs, window, retries, and queue policy are unchanged.
Local deliveries are excluded. Registration is once per component; no registry
lock is taken per packet. Existing tests plus partial-I/O counter tests pass.

The snapshot has process-wide per-component totals. Multiple endpoints using
the same component string are intentionally combined. The benchmarking driver
exports them without changing protocol events or control flow. In particular,
these counters must never affect a protocol decision or failure detector.
