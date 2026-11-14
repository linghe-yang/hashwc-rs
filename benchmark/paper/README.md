# Reproducing the WHCC paper figures

Run commands from the Rust repository root. The six-panel WAN figure is [coin-comparison.pdf](figures/coin-comparison.pdf). The recovery-quota figure is [sampling_compact.pdf](figures/sampling_compact.pdf). All published observations can be checked offline.

## What to reproduce

| Paper result | Frozen evidence | Measurement |
| --- | --- | --- |
| §7 recovery quotas | [Aptos snapshot](data/aptos/manifest.json), [825 plotted values](results/sampling-quota.csv) | Exact mean quota E/n for nested synthetic committees sampled with replacement. These are calculations, independent of network timing. |
| §9.2 honest dealers, left and middle columns | [30 original log archives and per-run tables](results/logs), [run measurements](results/measurements.csv), [paired means](results/paired-summary.csv), [published breakdown](results/paris-summary.json) | Full-coin sent bytes per party and longest local START-to-output. The Aptos latency breakdown uses Freeze and output on the same slowest party. Two runs per protocol/size in opposite orders. |
| §9.3 faulty dealers, right column | [16 individual measurements and raw log paths](results/faulty/runs.csv), [four two-run comparisons](results/faulty/path-summary.csv) | Mean **honest sender** bytes for PVR+Sampling or RBC full retrieval (MiB, divided by 2²⁰), including protocol framing and acknowledgments. Maximum honest local Freeze-to-last-required-outcome latency in seconds. Both exclude shared agreement. Two runs per protocol and size. Each point is the arithmetic mean of the two per-run metrics. Whiskers span their minimum and maximum. |

Sui epoch 1300 compares WHCC and virtual-share HashRand. Aptos epoch 17861 compares WHCC and the CSS-HashCoin warm-up. The honest matrix has 28 successes, two certified HashRand timeouts at 48 parties, and two skipped HashRand jobs at 64. Both 48-party timeout archives are retained. The [honest matrix](manifest.json), [faulty matrix](css-max-manifest.json), [committee inputs](inputs), [source snapshots](data), and [weight reduction certificates](reduction_checks) fix the samples. The honest campaign's [plan](results/original-plan.json) and [environment](results/original-environment.json) preserve the measured build fingerprints. Every faulty-run archive includes its own case, protocol parameters, execution settings, controller record, and party event streams.

The [faulty-dealer data guide](results/faulty/README.md) links each round to its raw logs and explains the §9.3 measurements and the two SSH incidents. The repository's top-level `results/` directory is a local workspace for campaign outputs. The archived paper data are under `benchmark/paper/results/`.

## Offline verification and figures

Use Python 3.11+; the log verifiers use only the standard library. For the figures, use Python 3.12, the dependencies below, and a TeX installation with PGFPlots and the standalone class. The commands write regenerated figures under a separate output directory.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r benchmark/paper/requirements.txt
python benchmark/paper/verify_results.py
python benchmark/paper/verify_faulty.py
mkdir -p results/replot
python benchmark/paper/figures/refresh_data.py --out results/replot/coin-comparison.tex
(cd results/replot && pdflatex -halt-on-error coin-comparison.tex)
python benchmark/paper/figures/sampling_quota.py --out results/replot
```

The first verifier checks SHA-256, reconstructs the honest-dealer measurements from the party logs, and compares the per-run CSVs. The second checks all 16 faulty runs, reconstructs the per-run metrics, and compares their two-run means and ranges with the four-size summary. To regenerate both `runs.csv` and `path-summary.csv` from the archives, run `python benchmark/paper/verify_faulty.py --write-summary` from the repository root. The WAN plot uses the verified tables and the raw slowest-party Freeze events. The quota script regenerates the committee stream from the snapshot with seed 20261055 and checks every plotted value. PDF metadata can differ between TeX or plotting-tool versions.

## Build and local smoke test

Use Linux, Rust with Cargo (the archived honest runs used rustc 1.99.0), and the committed Cargo.lock. Build release binaries for the same architecture as the AWS hosts (x86-64). Use a fresh directory for each preparation and run. On WSL, use a native Linux directory (for example under ~/) for prepared plans. Generating the 64-party configuration on a Windows-mounted directory can exceed the generator timeout.

```sh
cargo build --release --locked --bin coin-benchmark-driver --bin csshashcoin-node
python benchmark/paper/prepare.py --smoke --directory results/prepared-smoke
python benchmark/paper/local.py --prepared results/prepared-smoke --out results/local-smoke
```

The smoke plan runs all three protocols on two four-party inputs. Local timing reflects a shared machine. For the full honest loopback matrix, replace the smoke preparation with the honest plan below and use it with `local.py`.

## Re-run the five-region WAN experiments

One EC2 t3a.medium (2 vCPUs, 4 GiB, unlimited CPU credits) hosts each physical party. Regions are Northern Virginia, Ohio, Oregon, Tokyo and Paris; slot 0 also hosts the controller. Each run requests one bit, 40-bit rounding and a 180-second online timeout. WHCC uses 40-bit sampling coverage and four-column modules.

Prepare and validate both plans offline:

```sh
python benchmark/paper/prepare.py --directory results/prepared-honest
python benchmark/paper/campaign.py --prepared results/prepared-honest
python benchmark/paper/prepare.py --css-max --directory results/prepared-faulty
python benchmark/paper/campaign.py --prepared results/prepared-faulty
```

For a paid rerun, install and configure AWS CLI v2 and OpenSSH. Fill a private copy of [fleet.example.json](../aws_fleet/fleet.example.json) with the Ubuntu x86-64 AMI, subnet, security group, and imported SSH key name for each region. The Ubuntu hosts need Python 3.11+. Supply the matching local private key. For example:

```sh
python benchmark/paper/campaign.py --apply --prepared results/prepared-honest --config /path/to/fleet.json --key ~/.ssh/whcc-aws --out results/aws-honest
python benchmark/paper/campaign.py --apply --prepared results/prepared-faulty --config /path/to/fleet.json --key ~/.ssh/whcc-aws --out results/aws-faulty-r1
python benchmark/paper/campaign.py --apply --prepared results/prepared-faulty --config /path/to/fleet.json --key ~/.ssh/whcc-aws --out results/aws-faulty-r2
```

Each faulty campaign runs each protocol once at each size. Run both faulty commands to reproduce the two observations per point. The launcher expands from the smallest committee, checks SSH readiness, deploys the measured binary and configurations, checks worker errors, downloads and verifies logs, and cleans up the fleet. Formal logs are the default. Each completed job writes raw events and per-run CSVs in its size directory; faulty jobs additionally write `recovery.csv`. Fresh WAN timings and randomized assignments may differ. If interrupted, use the corresponding campaign directory for cleanup:

```sh
python benchmark/paper/campaign.py --apply --cleanup --config /path/to/fleet.json --out results/aws-faulty-r1
```
