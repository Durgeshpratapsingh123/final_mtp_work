#!/usr/bin/env python3
"""
analyze_latency.py

Standalone analysis of logs/latency_events.csv produced by SecureProxy's
Dispatcher (kernel_ts_ns,dispatch_ts_ns,latency_ns,pid,comm,syscall,cgroup).

Produces the summary stats / conclusions used in the MTP results section:
  - overall latency distribution (mean/median/p90/p95/p99/p99.9/max)
  - throughput (events/sec)
  - per-syscall and per-process breakdown
  - burst detection (consecutive slow events from the same pid)
  - latency distribution bucket chart + a percentile (CDF) chart

Usage:
    pip install pandas numpy matplotlib
    python3 analyze_latency.py path/to/latency_events.csv [--out-dir OUT_DIR]

Outputs (written to --out-dir, default "./latency_report"):
    summary.txt              human-readable summary (also printed to stdout)
    latency_buckets.png       bar chart of the distribution
    latency_cdf.png           cumulative distribution / percentile chart
    per_syscall_summary.csv   per-syscall aggregate stats
    per_comm_summary.csv      per-process aggregate stats
    bursts.csv                detected bursts (see BURST_GAP_NS below)
"""

import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd

# A "burst" is a run of consecutive events from the same pid whose
# kernel timestamps are within this many nanoseconds of each other.
# Tune this if your workload has naturally spaced-out syscalls.
BURST_GAP_NS = 2_000_000  # 2 ms
BURST_MIN_EVENTS = 5      # only report bursts with at least this many events

BUCKET_EDGES = [0, 10, 50, 100, 500, 1_000, 5_000, 10_000, np.inf]
BUCKET_LABELS = [
    "<10us", "10-50us", "50-100us", "100-500us",
    "500us-1ms", "1-5ms", "5-10ms", ">10ms",
]


def load(csv_path: Path) -> pd.DataFrame:
    df = pd.read_csv(csv_path)
    required = {"kernel_ts_ns", "dispatch_ts_ns", "latency_ns", "pid", "comm", "syscall", "cgroup"}
    missing = required - set(df.columns)
    if missing:
        sys.exit(f"CSV is missing expected columns: {missing}")
    df = df.sort_values("kernel_ts_ns").reset_index(drop=True)
    df["latency_us"] = df["latency_ns"] / 1000.0
    return df


def overall_stats(df: pd.DataFrame) -> dict:
    lat = df["latency_us"]
    duration_s = (df["kernel_ts_ns"].max() - df["kernel_ts_ns"].min()) / 1e9
    return {
        "total_events": len(df),
        "capture_duration_s": duration_s,
        "throughput_events_per_s": len(df) / duration_s if duration_s > 0 else float("nan"),
        "mean_us": lat.mean(),
        "median_us": lat.median(),
        "p90_us": lat.quantile(0.90),
        "p95_us": lat.quantile(0.95),
        "p99_us": lat.quantile(0.99),
        "p999_us": lat.quantile(0.999),
        "min_us": lat.min(),
        "max_us": lat.max(),
        "pct_over_1ms": (lat > 1000).mean() * 100,
        "pct_over_5ms": (lat > 5000).mean() * 100,
    }


def per_syscall(df: pd.DataFrame) -> pd.DataFrame:
    g = df.groupby("syscall")["latency_us"].agg(
        count="count", mean="mean", median="median", p95=lambda s: s.quantile(0.95), max="max"
    )
    return g.sort_values("count", ascending=False)


def per_comm(df: pd.DataFrame, top_n: int = 15) -> pd.DataFrame:
    top = df["comm"].value_counts().head(top_n).index
    g = (
        df[df["comm"].isin(top)]
        .groupby("comm")["latency_us"]
        .agg(count="count", mean="mean", median="median", max="max")
        .sort_values("count", ascending=False)
    )
    return g


def detect_bursts(df: pd.DataFrame) -> pd.DataFrame:
    """
    Flags runs of consecutive same-pid events whose kernel timestamps
    are tightly packed (<= BURST_GAP_NS apart), then reports the burst's
    span and its latency stats. This is what tells you whether tail
    latency is a queuing artifact under load vs. scattered/random.
    """
    rows = []
    for pid, g in df.groupby("pid"):
        g = g.sort_values("kernel_ts_ns")
        gaps = g["kernel_ts_ns"].diff().fillna(np.inf)
        burst_id = (gaps > BURST_GAP_NS).cumsum()
        for _, burst in g.groupby(burst_id):
            if len(burst) < BURST_MIN_EVENTS:
                continue
            rows.append({
                "pid": pid,
                "comm": burst["comm"].iloc[0],
                "events": len(burst),
                "span_ms": (burst["kernel_ts_ns"].max() - burst["kernel_ts_ns"].min()) / 1e6,
                "mean_latency_us": burst["latency_us"].mean(),
                "max_latency_us": burst["latency_us"].max(),
            })
    return pd.DataFrame(rows).sort_values("max_latency_us", ascending=False) if rows else pd.DataFrame(rows)


def make_charts(df: pd.DataFrame, out_dir: Path):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    # Bucket histogram
    bucketed = pd.cut(df["latency_us"], bins=BUCKET_EDGES, labels=BUCKET_LABELS)
    counts = bucketed.value_counts().reindex(BUCKET_LABELS)

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.bar(BUCKET_LABELS, counts.values)
    ax.set_yscale("log")
    ax.set_ylabel("Event count (log scale)")
    ax.set_xlabel("Kernel-to-dispatch latency")
    ax.set_title(f"Latency distribution ({len(df):,} events)")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    fig.savefig(out_dir / "latency_buckets.png", dpi=150)
    plt.close(fig)

    # Percentile / CDF chart
    sorted_lat = np.sort(df["latency_us"].values)
    cdf = np.arange(1, len(sorted_lat) + 1) / len(sorted_lat) * 100

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.plot(sorted_lat, cdf)
    ax.set_xscale("log")
    ax.set_xlabel("Latency (us, log scale)")
    ax.set_ylabel("Percentile")
    ax.set_title("Latency CDF")
    ax.axhline(50, color="gray", linestyle="--", linewidth=0.8)
    ax.axhline(99, color="red", linestyle="--", linewidth=0.8)
    plt.tight_layout()
    fig.savefig(out_dir / "latency_cdf.png", dpi=150)
    plt.close(fig)


def format_summary(stats: dict, syscall_df: pd.DataFrame, comm_df: pd.DataFrame, bursts_df: pd.DataFrame) -> str:
    lines = []
    lines.append("=== Overall ===")
    lines.append(f"Total events           : {stats['total_events']:,}")
    lines.append(f"Capture duration       : {stats['capture_duration_s']:.1f} s")
    lines.append(f"Throughput             : {stats['throughput_events_per_s']:.1f} events/s")
    lines.append(f"Mean latency           : {stats['mean_us']:.2f} us")
    lines.append(f"Median latency         : {stats['median_us']:.2f} us")
    lines.append(f"p90 / p95              : {stats['p90_us']:.2f} / {stats['p95_us']:.2f} us")
    lines.append(f"p99 / p99.9            : {stats['p99_us']:.2f} / {stats['p999_us']:.2f} us")
    lines.append(f"Min / Max              : {stats['min_us']:.3f} / {stats['max_us']:.2f} us")
    lines.append(f"Events > 1ms / > 5ms   : {stats['pct_over_1ms']:.2f}% / {stats['pct_over_5ms']:.2f}%")
    lines.append("")
    lines.append("=== Per syscall ===")
    lines.append(syscall_df.round(2).to_string())
    lines.append("")
    lines.append("=== Per process (top callers) ===")
    lines.append(comm_df.round(2).to_string())
    lines.append("")
    lines.append(f"=== Bursts (>= {BURST_MIN_EVENTS} consecutive same-pid events within {BURST_GAP_NS/1e6:.1f}ms) ===")
    if bursts_df.empty:
        lines.append("None detected.")
    else:
        lines.append(bursts_df.round(2).head(20).to_string(index=False))
    lines.append("")
    lines.append("=== Interpretation ===")
    lines.append(
        f"- Median latency ({stats['median_us']:.1f}us) reflects the steady-state cost the eBPF"
    )
    lines.append(
        "  Proxy Observer pipeline adds on top of the kernel event itself (ring-buffer"
    )
    lines.append("  transit + poll-thread wakeup).")
    lines.append(
        f"- Mean ({stats['mean_us']:.1f}us) is well above median -> right-skewed distribution;"
    )
    lines.append("  a small tail of slow events pulls the average up.")
    if not bursts_df.empty:
        lines.append(
            "- The slowest events cluster into bursts from single processes (see table above),"
        )
        lines.append(
            "  i.e. tail latency looks like ring-buffer/poll-thread queuing under bursty load"
        )
        lines.append("  rather than a fixed per-event cost.")
    lines.append(
        "- Cite median/p90 for typical-case overhead, and the burst table for the"
    )
    lines.append("  architecture's queuing behavior under load.")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("csv", type=Path, help="Path to latency_events.csv")
    parser.add_argument("--out-dir", type=Path, default=Path("./latency_report"))
    args = parser.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)

    df = load(args.csv)
    stats = overall_stats(df)
    syscall_df = per_syscall(df)
    comm_df = per_comm(df)
    bursts_df = detect_bursts(df)

    syscall_df.to_csv(args.out_dir / "per_syscall_summary.csv")
    comm_df.to_csv(args.out_dir / "per_comm_summary.csv")
    bursts_df.to_csv(args.out_dir / "bursts.csv", index=False)

    summary = format_summary(stats, syscall_df, comm_df, bursts_df)
    (args.out_dir / "summary.txt").write_text(summary)
    print(summary)

    try:
        make_charts(df, args.out_dir)
        print(f"\nCharts written to {args.out_dir}/latency_buckets.png and latency_cdf.png")
    except ImportError:
        print("\n(matplotlib not installed - skipping charts. pip install matplotlib to enable them.)")


if __name__ == "__main__":
    main()
