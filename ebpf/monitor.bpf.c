// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "monitor.h"

char LICENSE[] SEC("license") = "GPL";

/* Ring Buffer */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);   // 16 MB
} events SEC(".maps");


SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    /* Process information */

    u64 pid_tgid = bpf_get_current_pid_tgid();

    e->pid = pid_tgid >> 32;
    e->tid = (__u32)pid_tgid;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* Event type */

    e->event_type = EVENT_OPENAT;

    /* Timestamp */

    e->timestamp_ns = bpf_ktime_get_ns();

    /* Current cgroup */

    e->cgroup_id = bpf_get_current_cgroup_id();

    /* Namespace IDs (will be implemented in Version 2) */

    e->mnt_ns = 0;
    e->pid_ns = 0;

    /* Read filename argument */

    const char *filename = (const char *)ctx->args[1];

    bpf_probe_read_user_str(
        e->filename,
        sizeof(e->filename),
        filename);

    bpf_ringbuf_submit(e, 0);

    return 0;
}