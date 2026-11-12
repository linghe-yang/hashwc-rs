# Reproducing the single-coin evaluation

The archived experiment used one AWS `t3a.medium` per physical party, unlimited CPU credits, and five regions (Northern Virginia, Ohio, Oregon, Tokyo, Paris). The controller shared slot 0 with a party. Each committee size (16, 32, 48, 64) used the same frozen weights for both protocols in a pair. Sui compares WHCC with HashRand; Aptos compares WHCC with the CSS-HashCoin warm-up. Each pair ran twice in opposite protocol order, with one output bit, 40-bit statistical parameters and a 180-second online deadline after START.

## Published data

| Location | Contents |
|---|---|
| [measurements.csv](results/measurements.csv) | One row per scheduled run. Of 32 rows, 28 are successes, two are Sui HashRand timeouts at 48 parties, and two are skips at 64. |
| [paired-summary.csv](results/paired-summary.csv) | Means over completed pairs; timed-out or skipped jobs do not contribute success metrics. |
| [logs](results/logs), [verified.json](results/verified.json) | The 30 actual cloud log archives, original checksums, controller status, per-run CSVs, CPU/RSS samples and component counters. |
| [inputs](inputs), [manifest.json](manifest.json), [data](data), [reduction_checks](reduction_checks) | Eight exact committee inputs, snapshot provenance and lossless reduction certificates. |
| [original plan](results/original-plan.json), [original environment](results/original-environment.json) | Historical settings, binary hashes and source fingerprints at measurement time. New preparations record their own fingerprints. |
| [figures](figures) | The paper's four-panel figure and the supplementary per-chain plots. |

Traffic is measured over the complete service lifetime, including protocol acknowledgments and application retries. Published latency is the maximum party-local START-to-output interval. The Aptos latency breakdown uses Freeze and output from the same party in each run. The traffic breakdown separates common control (WRA, WGather, WBinAA) from distribution and recovery. The timeout concerns the online phase; preparation and post-output service have separate limits.

## Verify and replot

Run commands from the repository root. Log verification needs Python 3.11 or later. For plotting and running the experiment, the tested environment used Linux, Python 3.12, and Rust 1.99.0. Install TeX Live with PGFPlots and the standalone class for the paper figure.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r benchmark/paper/requirements.txt
python benchmark/paper/verify_results.py
python benchmark/paper/plot_paired.py --out results/replot
python benchmark/paper/figures/refresh_data.py
(cd benchmark/paper/figures && pdflatex -halt-on-error coin-comparison.tex)
```

Verification checks the archives against their SHA-256 digests, reconstructs the observations and CSV breakdowns, and compares them with the published tables. The last two commands regenerate the paper's embedded PGFPlots data and PDF. The supplementary plotting script also accepts a fresh run directory containing `measurements.csv`.

## Local run

```sh
cargo build --release --locked --bin coin-benchmark-driver --bin csshashcoin-node
python benchmark/paper/prepare.py --smoke --directory results/prepared-smoke
python benchmark/paper/local.py --prepared results/prepared-smoke --out results/local-smoke
```

The smoke plan runs all three protocols on an equal and a near-equal four-party committee. Each party is a separate process. For the complete local matrix, run the following commands. All local parties share the host's CPU and memory; local timing should be reported separately from WAN timing.

```sh
python benchmark/paper/prepare.py
python benchmark/paper/local.py --out results/local-paper
python benchmark/paper/plot_paired.py results/local-paper --out results/local-plots
```

Preparation validates the weight certificates, builds each protocol description, and freezes copies of the release binaries, inputs, parameters and hashes under `results/prepared-paper`. Specify `--directory` and then `--prepared` to use a different location. Local and cloud runners require a new output directory for each campaign and preserve the logs of failed runs.

## AWS run

Install AWS CLI v2 and OpenSSH on the control machine. Configure AWS CLI credentials and an SSH key pair imported in all five regions. Copy [fleet.example.json](../aws_fleet/fleet.example.json) to a private local fleet file. In each region supply an x86-64 Ubuntu AMI with Python 3.11+ and SSH, a public subnet supporting t3a.medium, and a dedicated security group named `whcc-benchmark` allowing SSH from the control machine. The key name in the file must match the AWS key pair. Set `--key` to the corresponding local private key. The fleet controller checks resources, allocates round-robin, tests SSH, and manages experiment-scoped peer rules and instance cleanup.

```sh
# Prepare once unless the same frozen full plan already exists.
python benchmark/paper/prepare.py

# Offline matrix and binary checks (no AWS calls).
python benchmark/paper/campaign.py

# Launch the paid campaign and download each stage's logs.
python benchmark/paper/campaign.py --apply --config /path/to/fleet.json --key ~/.ssh/whcc-aws --out results/aws-paper
```

The default SSH route is direct. The original control machine's local HTTP proxy can be selected with `--ssh-proxy` (netcat at 127.0.0.1:7890). Cloud jobs use the AWS-hosted controller for the measured interval. Each completed stage is audited before expansion. Two verified HashRand online timeouts at one size skip larger HashRand cases. Other failures abort the campaign and trigger cleanup. If the local launcher is interrupted before cleanup completes, use the same output directory and fleet configuration:

```sh
python benchmark/paper/campaign.py --apply --cleanup --config /path/to/fleet.json --out results/aws-paper
```

Fresh cloud output contains per-stage controller and worker logs, per-job analysis, `measurements.csv`, `paired-summary.csv`, plots and the cleanup record. Account-specific fleet settings, SSH keys and generated node credentials belong outside the published evidence.
