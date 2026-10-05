# Controlled WHCC scalability experiments

Generate the approved experiment matrix from the benchmark directory:

```sh
fab matrix --nodes=4,16,31,46,64 --scales=1,10,100 --mean-weight=300 --runs=3
fab local --policy=policies/controlled-scalability.json --output=file
fab plot --config=plot-configs/controlled-scalability.json
```

This produces 120 cases / 360 coin runs. Policies for each individual node count are also saved in policies/controlled-scalability/. The plot task reads saved results only.

For each n and distribution, construct a positive integer base weight vector with W=300n and T=100n. Scale every weight, T, and the inclusive corruption budget F=T-1 by 1, 10, or 100. The selected Byzantine identities remain fixed across those scales. Thus W/n, T/W, the normalized weights, and the actual corrupted weight fraction are controlled within the appropriate comparisons. F at scale s is (100n-1)s, not 100ns-1.

The four reference distributions are uniform; near-uniform [299,301]; a minority-heavy reference [10 repeated 99 times,110]; and the pinned Aptos snapshot in data/aptos-mainnet-v7479751174. Rank-quantile integration resamples each fixed reference to n parties, and Hamilton apportionment rounds to total 300n. This preserves the reference Lorenz curve at the sampled quantiles before integer rounding. Finite-n distributions are approximations, not identical vectors. Near-uniform base weights have gcd=1; scaling intentionally changes the gcd. The heavy reference keeps even the n=4 maximum below the corruption budget. Its finite-n heavy-party fraction varies due to discrete parties; the source population and concentration stay fixed. Aptos weights may individually exceed the corruption budget, so those identities cannot be corrupted in this fault model.

The recovery-stress selection maximizes the number of affordable Byzantine identities, then locally improves their total weight with one-swap updates. This is a reproducible bounded adversary, not a proof of the globally worst runtime adversary. Both honest and recovery-stress results appear as separate curves.

Three party-count charts fix the scale at 1,10,100. Five weight charts fix n at 4,16,31,46,64 and use total W on a logarithmic horizontal axis. Each chart has latency and mean bytes sent per honest party, yielding 16 figures in PNG/PDF/SVG. A point is the arithmetic mean of the three independent runs, with observed minimum/maximum bars (not confidence intervals). Incomplete runs and packet-capture loss are invalid measurements. Pilot experiments use a distinct experiment id and are excluded.

Latency is measured at the synchronizer from START to matching FINISH weight > T. Bandwidth includes TCP payload up to STOP/exit and excludes synchronizer traffic. This is the full-public-record WRBC implementation. All processes share one local machine, so CPU, memory and loopback competition affect measured scalability. n^n gate-maximization is a separate joint stress experiment and is not part of these controlled curves.

## Executed subset (user runtime limit)

The full 64-party Aptos scale-100 stress pilot completed in 361.541967 seconds. Following the user request to skip long 64-party tests, this batch runs the 96 cases / 288 coins for n=4,16,31,46. The full generated policies remain available. Execute the subset with `fab local --policy=policies/controlled-scalability-run.json --output=file`, then `fab plot --config=plot-configs/controlled-scalability-run.json`. This produces 14 figures, each in three formats. The omitted 64-party cases are listed in policies/controlled-scalability-skipped.json; no interpolated points replace them.

A pilot exposed excessive duplicate allocations in per-recipient broadcast queues. The transport now shares identical serialized pending payloads with weak-reference caching, retaining independent peer queues, retries, authenticated ACKs and the existing wire format. All formal runs use this same implementation. The pilot also exposed capture-statistics parsing of an intermediate SIGUSR1 status line; parsing now uses final counters and has a regression test. Replaying the complete pilot capture confirmed zero loss and full sender attribution. Pilot runs remain excluded from formal curves.

## Completed batch

All 96 selected configurations completed with three valid independent runs each (288 distinct session/epoch pairs). Every selected run has zero packet-capture drops and complete sender-byte attribution. Binary, transport, benchmark-source and environment metadata each form a single collected cohort. The final renderer was refined after collection to label W/n, use logarithmic party-chart y axes, and place legends outside the data area.

Three formal case attempts failed capture validation (69,186, 29,236 and 6 dropped packets); their records remain present and excluded. The two affected configurations were rerun in full until three valid runs were collected. During the remaining batch, clean cache pages for closed captures in this experiment were discarded between configurations with POSIX_FADV_DONTNEED, retaining all files and leaving protocol/capture parameters unchanged. Two earlier pilot failures and two successful small pilots are also excluded. This is an exploratory local benchmark; repetition and order-dependent machine load should be considered when interpreting performance differences.

The plotted legacy profile id heavy-tail is labeled Minority-heavy: it represents the fixed two-level minority-heavy reference, not a fitted power-law distribution. Bandwidth is sent TCP payload per honest party per coin, not a transfer rate. Weight scaling can yield non-monotonic circuit sizes because the current circuit uses the integer binary representation; gates are recorded separately.

Validation and per-configuration statistics: data/controlled-scalability-validation.json. Circuit sizes (including retained unrun 64-party policies): policies/controlled-scalability.gates.json. Figure index: plots/controlled-scalability/index.html. Raw results and captures occupy approximately 134 GiB and were retained for auditing.
