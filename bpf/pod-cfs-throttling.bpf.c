/* SPDX-License-Identifier: MIT */
/*
 * Per-pod CFS throttle duration: how long each per-CPU run queue of a
 * throttled cgroup stayed frozen before being unthrottled. cAdvisor tells
 * you *that* you were throttled; this tells you *how long* each stall was.
 */
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include "pod.bpf.h"

#define MAX_PODS 1024
#define NUM_BUCKETS 4 /* <=10ms, <=80ms, catch-all, sum */
#define POD_T1_US 10000
#define POD_T2_US 80000

struct hist_key {
    struct pod_uid pod;
    u64 bucket;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_PODS * NUM_BUCKETS);
    __type(key, struct hist_key);
    __type(value, u64);
} pod_cfs_throttled_seconds SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, NODE_HIST_SLOTS + 1);
    __type(key, u32);
    __type(value, u64);
} node_cfs_throttled_seconds SEC(".maps");

SEC("fentry/unthrottle_cfs_rq")
int BPF_PROG(unthrottle_cfs_rq, struct cfs_rq *cfs_rq)
{
    u64 clock = cfs_rq->rq->clock;
    u64 throttled_clock = cfs_rq->throttled_clock;
    if (!throttled_clock || clock < throttled_clock) {
        return 0;
    }
    u64 throttled_us = (clock - throttled_clock) / 1000;

    node_hist_observe(&node_cfs_throttled_seconds, throttled_us);

    struct hist_key key = {};
    if (!cgroup_to_pod_uid_btf(cfs_rq->tg->css.cgroup, &key.pod)) {
        return 0;
    }

    key.bucket = coarse_bucket(throttled_us, POD_T1_US, POD_T2_US);
    increment_map(&pod_cfs_throttled_seconds, &key, 1);
    key.bucket = SUM_KEY;
    increment_map(&pod_cfs_throttled_seconds, &key, throttled_us);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
