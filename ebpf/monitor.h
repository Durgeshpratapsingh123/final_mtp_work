#ifndef __MONITOR_H__
#define __MONITOR_H__

#include <linux/types.h>

#define MAX_FILENAME_LEN 256
#define TASK_COMM_LEN 16

/* Types of events we may monitor */
enum event_type {
    EVENT_OPENAT = 1,
    EVENT_READ,
    EVENT_WRITE,
    EVENT_EXECVE,
};

/*
 * Event sent from eBPF program to user-space.
 *
 * Uses the fixed-width __u32/__u64 types from <linux/types.h> (as
 * opposed to the vmlinux.h-only u32/u64 aliases) so this header is
 * safe to include from both the BPF program and plain userspace
 * C/C++ code such as EbpfManager/Dispatcher.
 */
struct event {
    /* Process information */
    __u32 pid;
    __u32 tid;

    char comm[TASK_COMM_LEN];

    /* Namespace information */
    __u64 mnt_ns;
    __u64 pid_ns;
    __u64 cgroup_id;

    /* Event information */
    __u32 event_type;

    /* Timestamp */
    __u64 timestamp_ns;

    /* File information */
    char filename[MAX_FILENAME_LEN];
};

#endif
