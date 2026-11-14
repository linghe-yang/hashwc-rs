# Faulty-dealer recovery data (§9.3)

| Data | How to use it |
| --- | --- |
| [Individual runs](runs.csv) | One row per size, protocol and round. The `archive` column gives the raw log path relative to this directory. The first-round measurements (`round=1`) underlie the numerical examples in the introduction and §9.3. |
| [Figure data](path-summary.csv) | One row per committee size. Each plotted value averages the two individual runs with equal weight. For each metric, mean ± `_half_range` gives the two observed endpoints. |
| [Archive digests](checksums.json) | SHA-256 for each of the 16 raw archives, keyed by its directory name. |
| [Frozen settings](run-settings.json) and [worker file-descriptor limits](worker-nofile.csv) | Per-size settings and binary hashes, and per-worker limits observed in both 80-party rounds. |

## Reading a run

The `whcc` protocol uses PVR with sampling. The `warmup` protocol uses RBC full retrieval. Both path metrics exclude shared agreement traffic.

- `path_mib_per_honest` divides all honest senders' bytes on the distribution and recovery path by the number of honest parties and by 2²⁰.
- `max_honest_recovery_s` is the longest local interval across honest parties, from Freeze until that party had the last required dealer outcome.
- `reject_mib_per_honest` counts the rejection-certificate payload sent by honest parties, once per remote recipient, in MiB per honest party. It is part of the path traffic.
- In the figure table, a negative `pvr_vs_rbc_traffic_pct` means WHCC sent fewer bytes. The percentage compares the two protocol means.

For example, the [80-party WHCC second run](aptos-n80--whcc-r2/) contains the original controller archive (`cloud-logs.tar.gz`), the path-only table (`recovery.csv`), and the detailed counters (`measurement.csv`). Directory suffixes `-r1` and `-r2` identify the round in the index. Both rounds used the frozen one-run plan, so both retain the original job suffix `-r1` and internal repeat value 1.

## Run conditions

At 32, 48, 64 and 80 parties the adversary controlled 18, 26, 35 and 46 dealers, respectively. Dealers were selected in increasing stake order while their total stake remained strictly below one third. Each flipped one bit in every OR-gate correction before committing. Each size used the same protocol order in both rounds. At 80 parties every worker used a soft file-descriptor limit of 65,536.

In round 2 at 48 parties, WHCC completed before an SSH failure during warm-up setup. Warm-up then ran on fresh instances with the same five-region placement. In round 2 at 64 parties, SSH timed out during remote directory cleanup after WHCC logs had been downloaded. All 64 workers agreed on the coin and exited with code zero. The per-run tables were reconstructed offline from those logs.

From the repository root, run `python benchmark/paper/verify_faulty.py` to verify both tables against the archives. The [reproduction instructions](../../README.md) cover replotting and rerunning the five-region experiments.
