"""Polynomial, certified weight reduction. No coalition enumeration or solver.

Candidate *sums*, rather than input weight magnitudes, are bounded by c*n*n.
The exact min/max dynamic program proves statements about ALL coalitions.
NumPy is an optional integer-only acceleration of the same recurrence.
"""
from __future__ import annotations

import hashlib
import json
import math
import time
from dataclasses import dataclass
from decimal import Decimal, localcontext

VERSION = "bounded-sum-exact-integer-v2"
DEFAULT_BUDGET_FACTOR = 1024


def validate(weights, threshold):
    if not weights or any(type(w) is not int or w <= 0 for w in weights):
        raise ValueError("weights must be nonempty positive Python integers")
    if type(threshold) is not int or not 0 < threshold <= sum(weights):
        raise ValueError("require integer 0 < threshold <= total")


def digest(weights, threshold):
    data = json.dumps([list(map(str, weights)), str(threshold)], separators=(",", ":"))
    return hashlib.sha256(data.encode()).hexdigest()


@dataclass
class Extremes:
    low: object
    high: object
    backend: str
    total: int

    def cutoff_interval(self, q):
        """All integer u with old(A)>=q iff new(A)>=u, including endpoints."""
        if self.backend == "numpy-int64":
            import numpy as np
            losers = np.flatnonzero((self.low >= 0) & (self.low < q))
            winners = np.flatnonzero(self.high >= q)
            return (int(losers[-1]) + 1 if len(losers) else 0,
                    int(winners[0]) if len(winners) else self.total + 1)
        losing, winning = -1, self.total + 1
        for s, (lo, hi) in enumerate(zip(self.low, self.high)):
            if lo >= 0 and lo < q:
                losing = s
            if hi >= q and s < winning:
                winning = s
        return losing + 1, winning


def extremes(weights, proposed, budget, backend="auto"):
    if len(weights) != len(proposed) or any(type(v) is not int or v <= 0 for v in proposed):
        raise ValueError("one positive integer proposed weight per party")
    total = sum(proposed)
    if total > budget:
        raise ValueError("candidate sum exceeds polynomial budget")
    if backend not in ("auto", "python", "numpy"):
        raise ValueError("unknown backend")
    use_numpy = False
    # Every performed sum is <= W. No float or uint conversion is used.
    if backend != "python" and sum(weights) <= (1 << 63) - 2:
        try:
            import numpy as np
            use_numpy = True
        except ImportError:
            if backend == "numpy":
                raise
    if use_numpy:
        low = np.full(total + 1, -1, dtype=np.int64)
        high = np.full(total + 1, -1, dtype=np.int64)
        low[0] = high[0] = 0
        bound = 0
        for old, new in zip(weights, proposed):
            # Copies are essential: source and destination slices overlap.
            lo = low[:bound + 1].copy()
            hi = high[:bound + 1].copy()
            reachable = lo >= 0
            lo[reachable] += old
            hi[reachable] += old
            target_low = low[new:new + bound + 1]
            take = reachable & ((target_low < 0) | (lo < target_low))
            target_low[take] = lo[take]
            np.maximum(high[new:new + bound + 1], hi,
                       out=high[new:new + bound + 1])
            bound += new
        return Extremes(low, high, "numpy-int64", total)
    low, high = [-1] * (total + 1), [-1] * (total + 1)
    low[0] = high[0] = 0
    bound = 0
    for old, new in zip(weights, proposed):
        for s in range(bound, -1, -1):
            if low[s] < 0:
                continue
            target, lo, hi = s + new, low[s] + old, high[s] + old
            if low[target] < 0 or lo < low[target]:
                low[target] = lo
            if hi > high[target]:
                high[target] = hi
        bound += new
    return Extremes(low, high, "python-bigint", total)


def inspect_candidate(weights, threshold, proposed, budget, backend="auto"):
    """Produce exact certificates for CSS-only and whole-policy replacement.

    Strong mode preserves sign(w(A)-T) and sign(3w(A)-W), for every A.
    Complementation then preserves both W-T quorum inequalities and 2W/3.
    """
    validate(weights, threshold)
    dp = extremes(weights, proposed, budget, backend)
    total, new_total = sum(weights), dp.total
    queries = {threshold, threshold + 1, (total + 2) // 3, total // 3 + 1}
    intervals = {q: dp.cutoff_interval(q) for q in queries}
    css_lo, css_hi = intervals[threshold]
    css_lo, css_hi = max(1, css_lo), min(new_total, css_hi)
    strict_lo, strict_hi = intervals[threshold + 1]
    strong_lo = max(css_lo, strict_lo - 1)
    strong_hi = min(css_hi, strict_hi - 1, (new_total + 2) // 3)
    if threshold == (total + 2) // 3:
        strong_lo = max(strong_lo, (new_total + 2) // 3)
        strong_hi = min(strong_hi, (new_total + 2) // 3)
    ratio_checks = []
    for label, old_q, new_q in (
        ("at_least_one_third", (total + 2) // 3, (new_total + 2) // 3),
        ("strictly_more_than_one_third", total // 3 + 1, new_total // 3 + 1),
    ):
        lo, hi = intervals[old_q]
        ratio_checks.append(dict(predicate=label, old_cutoff=str(old_q),
                                 new_cutoff=new_q, feasible_interval=[lo, hi],
                                 preserved=lo <= new_q <= hi))
    strong_ok = (3 * (threshold - 1) < total and strong_lo <= strong_hi
                 and all(row["preserved"] for row in ratio_checks))
    return dict(method="exact-min-max-dp", backend=dp.backend, candidate_sum=new_total,
                css_threshold_interval=[css_lo, css_hi],
                css_threshold=css_lo if css_lo <= css_hi else None,
                strong_threshold_interval=[strong_lo, strong_hi],
                strong_threshold=strong_lo if strong_ok else None,
                cutoff_intervals={str(q): list(intervals[q]) for q in sorted(queries)},
                ratio_checks=ratio_checks)


def candidates(weights, budget):
    """Same finite deterministic proposal family for every n/distribution."""
    n, total = len(weights), sum(weights)
    max_target = budget - n
    if max_target < n:
        return []
    targets, current = [], n
    while current < max_target:
        targets.append(current)
        current *= 2
    targets.append(max_target)
    unique = {}
    for target in targets:
        for mode, offset in (("nearest", total // 2), ("floor", 0), ("ceil", total - 1)):
            proposed = tuple(max(1, (w * target + offset) // total) for w in weights)
            g = math.gcd(*proposed)
            proposed = tuple(v // g for v in proposed)
            if sum(proposed) < total and sum(proposed) <= budget:
                unique.setdefault(proposed, dict(target_sum=target, rounding=mode,
                                                  proposal_gcd=g))
    return [(list(v), unique[v]) for v in sorted(unique, key=lambda v: (sum(v), max(v), v))]


def result_record(weights, threshold, method, certificate):
    return dict(weights=list(map(str, weights)), threshold=str(threshold),
                total_weight=str(sum(weights)), total_weight_bits=sum(weights).bit_length(),
                sum_individual_weight_bits=sum(w.bit_length() for w in weights),
                max_weight_bits=max(weights).bit_length(), method=method,
                certificate=certificate, policy_sha256=digest(weights, threshold))


def reduce_weights(weights, threshold, budget_factor=DEFAULT_BUDGET_FACTOR, backend="auto"):
    """Always terminates in polynomial time; unchanged is a legitimate result.

    Fixed integer budget_factor gives O(n^3 log n) DP updates, each on O(log W)
    bits. This is NOT an optimizer for all equivalent weight representations.
    """
    validate(weights, threshold)
    if 3 * (threshold - 1) >= sum(weights):
        raise ValueError("whole-policy mode requires the original 3(T-1) < W")
    if type(budget_factor) is not int or not 1 <= budget_factor <= 1024:
        raise ValueError("budget_factor must be a fixed integer in 1..1024")
    start = time.perf_counter()
    n, total = len(weights), sum(weights)
    budget = budget_factor * n * n
    common = math.gcd(*weights)
    css = result_record([w // common for w in weights], (threshold + common - 1) // common,
                        "exact-weight-gcd", dict(divisor=str(common), scope="CSS-only"))
    common_policy = math.gcd(common, threshold)
    strong = result_record([w // common_policy for w in weights], threshold // common_policy,
                           "exact-policy-gcd", dict(divisor=str(common_policy),
                                                    scope="whole-policy"))
    attempts = []
    for proposed, recipe in candidates(weights, min(budget, total - 1)):
        if sum(proposed) >= int(strong["total_weight"]) and sum(proposed) >= int(css["total_weight"]):
            continue
        begin = time.perf_counter()
        check = inspect_candidate(weights, threshold, proposed, budget, backend)
        attempts.append(dict(**recipe, seconds=time.perf_counter() - begin, **check))
        if check["css_threshold"] is not None and sum(proposed) < int(css["total_weight"]):
            css = result_record(proposed, check["css_threshold"], "certified-bounded-dp", check)
        if check["strong_threshold"] is not None and sum(proposed) < int(strong["total_weight"]):
            strong = result_record(proposed, check["strong_threshold"], "certified-bounded-dp", check)
            # Proposals are ordered by sum. Later proposals cannot improve either result.
            break
    for result in (css, strong):
        result["reduced"] = int(result["total_weight"]) < total
        with localcontext() as ctx:
            ctx.prec = 10
            result["sum_reduction_factor"] = str(Decimal(total) / Decimal(result["total_weight"]))
    return dict(version=VERSION, n=n, input_policy_sha256=digest(weights, threshold),
                original=result_record(weights, threshold, "input", {}),
                budget_factor=budget_factor, candidate_sum_budget=budget,
                strong=strong, css_only=css, attempts=attempts,
                seconds=time.perf_counter() - start,
                meaning_of_failure="No certified improvement in this proposal family and budget; not impossibility")

