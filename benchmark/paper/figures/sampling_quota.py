"""Recompute the paper quota curve from the frozen Aptos snapshot."""
import argparse
import csv
from fractions import Fraction
from functools import lru_cache
from hashlib import sha256
import json
from pathlib import Path

def ceil_fraction(x):
    return (x.numerator + x.denominator - 1) // x.denominator


@lru_cache(None)
def log_ratio_upper(n, d):
    """Exactly the positive-series upper bound in recovery/src/lib.rs."""
    assert d <= n <= 2 * d
    z = Fraction(n - d, n + d)
    z2, power, total = z * z, z, Fraction(0)
    for j in range(64):
        total += power / (2 * j + 1)
        power *= z2
    return 2 * (total + power / ((1 - z2) * 129))


@lru_cache(None)
def budget(n, bits):
    if not (1 <= n <= 4096 and 1 <= bits <= 256):
        raise ValueError("outside the current Rust sampler's parameter domain")
    q = n.bit_length() - 1
    x = Fraction(3, 2) * (
        log_ratio_upper(2, 1) * (bits + q) + log_ratio_upper(n, 1 << q)
    )
    return ceil_fraction(x)


def epsilon_bits(exponent):
    """Smallest integer k with 2^-k <= 10^-exponent; no logarithm rounding."""
    return (10 ** exponent - 1).bit_length()


def omission_floor_direct(n, numerator, denominator, m):
    return n * pow(numerator, m) // pow(denominator, m)


def omission_floor(n, numerator, denominator, m):
    """Certified floor of n*(numerator/denominator)^m.

    Fixed-point outward-rounded intervals are squared log2(m) times.
    Return only if both endpoints have the same integer floor. Ambiguity
    increases precision, then falls back to the production integer expression.
    This accelerates analysis only; it does not replace any Rust code.
    """
    assert 0 <= numerator <= denominator and m > 0 and m & (m - 1) == 0
    for precision in (128, 256):
        scale = 1 << precision
        lower = numerator * scale // denominator
        upper = (numerator * scale + denominator - 1) // denominator
        for _ in range(m.bit_length() - 1):
            lower = lower * lower // scale
            upper = (upper * upper + scale - 1) // scale
        lo, hi = n * lower // scale, n * upper // scale
        if lo == hi:
            return lo
    return omission_floor_direct(n, numerator, denominator, m)


def quota_histogram(weights, bits, direct=False):
    if not weights or min(weights) <= 0:
        raise ValueError("weights must be positive and nonempty")
    n, total = len(weights), sum(weights)
    a = budget(n, bits)
    m = 1 << (max(1024, a) - 1).bit_length()
    base = m * total
    floor = omission_floor_direct if direct else omission_floor
    by_weight = {
        w: n - floor(n, base - a * w, base, m) for w in set(weights)
    }
    return a, m, by_weight


def quotas(weights, bits, direct=False):
    a, m, lookup = quota_histogram(weights, bits, direct)
    return a, m, [lookup[w] for w in weights]


def empirical_indices(chain, seed, size, pool_size):
    """One reproducible with-replacement stream, independent of epsilon and n.

    Rejection sampling removes modulo bias. Only weights are reused; positions
    represent distinct synthetic parties, not repeated identities in a network.
    """
    bound = (1 << 256) - ((1 << 256) % pool_size)
    indices = []
    for position in range(size):
        attempt = 0
        while True:
            payload = json.dumps(
                ["whcc-static-empirical-weights-v1", chain, seed, position, attempt],
                separators=(",", ":"), ensure_ascii=True,
            ).encode("ascii")
            value = int.from_bytes(sha256(payload).digest(), "big")
            if value < bound:
                indices.append(value % pool_size)
                break
            attempt += 1
    return indices



def main():
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    paper = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    out = parser.parse_args().out
    out.mkdir(parents=True, exist_ok=True)
    snapshot = json.loads((paper / "data/aptos/manifest.json").read_bytes())
    pool = [int(v["weight"]) for v in snapshot["validators"]]
    weights = [pool[i] for i in empirical_indices("aptos", 20261055, 2000, len(pool))]
    rows = []
    for n in [*range(16, 101), *range(110, 2001, 10)]:
        for exponent in (8, 10, 12):
            bits = epsilon_bits(exponent)
            a, m, values = quotas(weights[:n], bits)
            rows.append(dict(n=n, kappa=bits, assignments_E=sum(values)))
    with (paper / "results/sampling-quota.csv").open(newline="") as stream:
        expected = [{k: int(v) for k, v in row.items()} for row in csv.DictReader(stream)]
    if rows != expected:
        raise ValueError("quota curve differs from the published points")
    plt.rcParams.update({'font.family': 'serif', 'font.serif': ['STIXGeneral'],
                         'mathtext.fontset': 'stix', 'font.size': 8,
                         'axes.labelsize': 8, 'xtick.labelsize': 7,
                         'ytick.labelsize': 7, 'legend.fontsize': 8,
                         'pdf.fonttype': 42, 'svg.fonttype': 'none'})
    fig, ax = plt.subplots(figsize=(3.5, 1.5))
    for e, color, style in [(8, '#0072B2', '-'), (10, '#D55E00', '--'),
                             (12, '#009E73', '-.')]:
        rs = [r for r in rows if r['kappa'] == epsilon_bits(e)]
        ax.plot([r['n'] for r in rs], [r['assignments_E'] / r['n'] for r in rs],
                color=color, linestyle=style, linewidth=1.15,
                label=rf'$\varepsilon_{{\rm cov}}=10^{{-{e}}}$')
    ax.set_xlim(0, 2000)
    ax.set_xticks([0, 500, 1000, 1500, 2000])
    ax.set_xlabel('Number of parties, $n$', labelpad=1)
    ax.tick_params(length=2, pad=2)
    ax.spines[['top', 'right']].set_visible(False)
    ax.grid(axis='y', alpha=.2, linewidth=.5)
    ax.set_axisbelow(True)
    ax.set_ylim(0, 60)
    ax.set_yticks([0, 20, 40, 60])
    ax.set_ylabel('Mean quota, $E/n$', labelpad=1)
    fig.legend(*ax.get_legend_handles_labels(), loc='upper center',
               bbox_to_anchor=(.51, 1.015), ncol=3, frameon=False,
               columnspacing=.8, handlelength=1.7, handletextpad=.35)
    fig.subplots_adjust(left=.12, right=.955, bottom=.25, top=.77)
    fig.savefig(out / "sampling_compact.pdf")
    plt.close(fig)
    print(f"Verified {len(rows)} quota observations")


if __name__ == "__main__":
    main()
