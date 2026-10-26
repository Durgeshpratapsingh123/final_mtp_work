#!/usr/bin/env python3
"""
plot_scaling.py

Reads scaling_results.csv (from run_scaling_benchmark.sh) and produces:
  - scaling.png: avg open()+close() latency vs number of attached probes
  - a printed comparison: traditional approach's per-tenant marginal cost
    (slope of the N=1..40 line) vs the proposed approach's fixed cost
    (the N=1 point, since the shared design never attaches more than one
    program no matter how many tenants exist).

Usage:
    pip install pandas numpy matplotlib
    python3 plot_scaling.py scaling_results.csv
"""

import sys
from pathlib import Path

import numpy as np
import pandas as pd


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: python3 plot_scaling.py scaling_results.csv")

    df = pd.read_csv(sys.argv[1]).sort_values("n_probes")

    baseline = df[df["n_probes"] == 0]["avg_latency_ns"]
    baseline_ns = baseline.iloc[0] if len(baseline) else None

    proposed = df[df["n_probes"] == 1]["avg_latency_ns"]
    proposed_ns = proposed.iloc[0] if len(proposed) else None

    # Linear fit over N >= 1 to get the traditional approach's
    # marginal cost per additional tenant probe.
    fit_df = df[df["n_probes"] >= 1]
    slope, intercept = np.polyfit(fit_df["n_probes"], fit_df["avg_latency_ns"], 1)

    print(df.to_string(index=False))
    print()

    if baseline_ns is not None:
        print(f"No eBPF attached (N=0) baseline : {baseline_ns:.1f} ns/open")
    if proposed_ns is not None:
        print(f"Proposed (single shared probe)  : {proposed_ns:.1f} ns/open  <- fixed, regardless of tenant count")

    print(f"Traditional marginal cost/probe  : {slope:.1f} ns per additional tenant probe")
    print()

    for n_tenants in (5, 10, 20, 50, 100):
        traditional_estimate = intercept + slope * n_tenants
        print(
            f"At {n_tenants:>3} tenants -> traditional (N={n_tenants} probes) ~= "
            f"{traditional_estimate:.0f} ns/open vs proposed = {proposed_ns:.0f} ns/open "
            f"({traditional_estimate / proposed_ns:.1f}x)"
        )

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        fig, ax = plt.subplots(figsize=(8, 5))
        ax.plot(df["n_probes"], df["avg_latency_ns"], "o-", label="measured")

        xs = np.linspace(df["n_probes"].min(), df["n_probes"].max(), 100)
        ax.plot(xs, intercept + slope * xs, "--", alpha=0.5, label="linear fit (N>=1)")

        if proposed_ns is not None:
            ax.axhline(proposed_ns, color="green", linestyle=":", label="proposed (fixed, N=1)")

        ax.set_xlabel("Number of attached probes (N)")
        ax.set_ylabel("Avg open()+close() latency (ns)")
        ax.set_title("Per-syscall overhead: traditional (N probes) vs proposed (shared)")
        ax.legend()
        plt.tight_layout()

        out_path = Path("scaling.png")
        fig.savefig(out_path, dpi=150)
        print(f"\nChart written to {out_path}")
    except ImportError:
        print("\n(matplotlib not installed - skipping chart)")


if __name__ == "__main__":
    main()
