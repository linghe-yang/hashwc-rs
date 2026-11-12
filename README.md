# Weighted single-coin experiments

This Rust workspace implements WHCC, the CSS-HashCoin warm-up, and a single-output HashRand baseline with virtual shares. The paper evaluates one coin at a time. The common benchmark driver runs the selected protocol and records its outputs, communication counters and resource usage.

[Paper results, raw logs, figures and reproduction instructions](benchmark/paper/README.md) cover both Linux loopback and the five-region AWS experiment. The published figure is available as a [PDF](benchmark/paper/figures/coin-comparison.pdf).

Build the two experiment binaries from the repository root on Linux:

```sh
cargo build --release --locked --bin coin-benchmark-driver --bin csshashcoin-node
```

The warm-up is named `csshashcoin` in Rust and `warmup` in the result tables. Shared CSS, asynchronous sharing, recovery, coding, transport, configuration, and weighted control primitives are included with the protocol sources. The Cargo lockfile pins the external primitives; the local integer-threshold overlays are documented in [vendor/THRESHOLD_BOUNDARY.md](vendor/THRESHOLD_BOUNDARY.md).
