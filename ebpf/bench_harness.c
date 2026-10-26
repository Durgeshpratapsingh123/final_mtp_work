// bench_harness.c
//
// Benchmarks raw syscall (open+close) latency as a function of how many
// independent eBPF program instances are attached to the same
// sys_enter_openat tracepoint.
//
// This models the "traditional" per-tenant probe approach (N separate
// programs, N separate ring buffers, one per Container A/B/C.../tenant)
// against the shared single-instrumentation-point design in SecureProxy:
// in the proposed architecture only ONE program is ever attached
// regardless of tenant count, so its N=1 datapoint is the only kernel-side
// cost tenants actually pay, no matter how many tenants exist. Under the
// traditional approach, every additional tenant means another program
// attached to the same hookpoint, and the kernel runs every attached
// program on every occurrence of the event -- so this benchmark's N=5,
// N=10, N=20... datapoints show what that additional-tenant cost actually
// looks like on the raw syscall path.
//
// Usage:
//   ./bench_harness <N_probes> <iterations>
//
// Prints one CSV line to stdout:
//   n_probes,iterations,avg_latency_ns,total_time_ns
//
// Must be run as root (loading/attaching BPF programs requires
// CAP_BPF/CAP_SYS_ADMIN), and needs the same ebpf/ directory
// (monitor.h, monitor.skel.h, vmlinux.h) as SecureProxy itself --
// build from within SecureProxy/ebpf/ or point -I at it.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>

#include "monitor.skel.h"

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

int main(int argc, char **argv)
{
    if (argc != 3)
    {
        fprintf(stderr, "usage: %s <N_probes> <iterations>\n", argv[0]);
        return 1;
    }

    int n = atoi(argv[1]);
    int iterations = atoi(argv[2]);

    if (n < 0 || iterations <= 0)
    {
        fprintf(stderr, "N must be >= 0, iterations must be > 0\n");
        return 1;
    }

    struct monitor_bpf **skels = NULL;

    if (n > 0)
    {
        skels = calloc((size_t)n, sizeof(*skels));
        if (!skels)
        {
            perror("calloc");
            return 1;
        }

        // Load+attach N independent instances of the SAME compiled
        // program to the same tracepoint. This is exactly how N
        // separate per-tenant probes would coexist in the kernel --
        // each gets invoked on every sys_enter_openat.
        for (int i = 0; i < n; i++)
        {
            skels[i] = monitor_bpf__open_and_load();

            if (!skels[i])
            {
                fprintf(stderr, "failed to open/load probe instance %d\n", i);
                return 1;
            }

            if (monitor_bpf__attach(skels[i]))
            {
                fprintf(stderr, "failed to attach probe instance %d\n", i);
                return 1;
            }
        }
    }

    const char *path = "/tmp/bench_harness_target";

    int wfd = open(path, O_CREAT | O_WRONLY, 0644);
    if (wfd < 0)
    {
        perror("open(create)");
        return 1;
    }
    close(wfd);

    // Warm up page cache / TLB before timing so the first few
    // iterations don't skew the average.
    for (int i = 0; i < 200; i++)
    {
        int fd = open(path, O_RDONLY);
        if (fd >= 0) close(fd);
    }

    uint64_t start = now_ns();

    for (int i = 0; i < iterations; i++)
    {
        int fd = open(path, O_RDONLY);
        if (fd >= 0) close(fd);
    }

    uint64_t elapsed = now_ns() - start;
    double avg = (double)elapsed / iterations;

    printf("%d,%d,%.2f,%llu\n", n, iterations, avg, (unsigned long long)elapsed);

    for (int i = 0; i < n; i++)
    {
        monitor_bpf__destroy(skels[i]);
    }
    free(skels);

    unlink(path);

    return 0;
}
