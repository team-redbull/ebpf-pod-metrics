/* SPDX-License-Identifier: MIT */
/*
 * Per-pod OOM kills with the victim process name. Keyed by pod (not the
 * container cgroup), so the event survives the container being torn down
 * and restarted before the next scrape.
 */
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include "pod.bpf.h"

#define TASK_COMM_LEN 16

struct oom_key {
    struct pod_uid pod;
    char comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct oom_key);
    __type(value, u64);
} pod_oom_kills_total SEC(".maps");

SEC("kprobe/oom_kill_process")
int BPF_KPROBE(oom_kill_process, struct oom_control *oc)
{
    struct task_struct *victim = BPF_CORE_READ(oc, chosen);
    if (!victim) {
        return 0;
    }

    struct oom_key key = {};
    if (!task_to_pod_uid(victim, &key.pod)) {
        return 0;
    }

    BPF_CORE_READ_STR_INTO(&key.comm, victim, comm);
    increment_map(&pod_oom_kills_total, &key, 1);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
