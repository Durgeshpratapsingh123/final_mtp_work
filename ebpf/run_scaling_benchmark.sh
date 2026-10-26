#!/usr/bin/env bash
# Runs bench_harness for a range of "N attached probes" and collects the
# results. Run each N as a fresh process (not a loop inside one process)
# so each data point starts from a clean kernel attachment state.
#
# Usage: sudo ./run_scaling_benchmark.sh
set -euo pipefail

OUT="scaling_results.csv"
ITERATIONS=200000
N_VALUES=(0 1 2 5 10 20 40)

echo "n_probes,iterations,avg_latency_ns,total_time_ns" > "$OUT"

for n in "${N_VALUES[@]}"; do
    echo "Running N=$n probes, $ITERATIONS iterations..." >&2
    ./bench_harness "$n" "$ITERATIONS" >> "$OUT"
    sleep 1  # let the kernel fully tear down the previous run's probes
done

echo "Done. Results in $OUT" >&2
cat "$OUT"
