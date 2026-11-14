# Weighted single-coin experiments

This Rust workspace implements WHCC, the CSS-HashCoin warm-up, and a single-output HashRand baseline with virtual shares. The paper evaluates one coin at a time. The common benchmark driver runs the selected protocol and records its outputs, communication counters and resource usage.

[Paper results, raw logs, figures and reproduction instructions](benchmark/paper/README.md) cover both Linux loopback and the five-region AWS experiment. The published figure is available as a [PDF](benchmark/paper/figures/coin-comparison.pdf).

| Dataset | Individual runs | Figure data |
| --- | --- | --- |
| Honest dealers, full coin (§9.2) | [Measurements](benchmark/paper/results/measurements.csv) | [Paired means](benchmark/paper/results/paired-summary.csv) |
| Faulty dealers, recovery only (§9.3) | [16 runs and their raw log paths](benchmark/paper/results/faulty/runs.csv) | [Two-run means and ranges](benchmark/paper/results/faulty/path-summary.csv) |
| Recovery quotas (§7) | [Source snapshot](benchmark/paper/data/aptos/manifest.json) | [Quota table](benchmark/paper/results/sampling-quota.csv) |

Build the two experiment binaries from the repository root on Linux:

```sh
cargo build --release --locked --bin coin-benchmark-driver --bin csshashcoin-node
```

The warm-up is named `csshashcoin` in Rust and `warmup` in the result tables. Shared CSS, asynchronous sharing, recovery, coding, transport, configuration, and weighted control primitives are included with the protocol sources. The Cargo lockfile pins the external primitives; the local integer-threshold overlays are documented in [vendor/THRESHOLD_BOUNDARY.md](vendor/THRESHOLD_BOUNDARY.md).
