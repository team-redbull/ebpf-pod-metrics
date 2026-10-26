/* SPDX-License-Identifier: MIT */
/*
 * Per-pod CPU run-queue latency: time a thread spends runnable but waiting
 * for a CPU (wakeup/preemption -> actually scheduled). This is the signal
 * cAdvisor can't give you: noisy neighbours and CPU contention even when
 * the pod is nowhere near its CPU limit.
 *
 * Hot path (every context switch), so it is built for cost:
 *  - no wakeup hooks and no timestamp map: the scheduler already stamps
 *    task->sched_info.last_queued on enqueue (the same accounting behind
 *    /proc/<pid>/schedstat and delay accounting); we read it right before
 *    the kernel consumes it, against the same rq clock;
 *  - direct BTF loads instead of bpf_probe_read helpers;
 *  - per-CPU counters, so pods spread over many CPUs don't bounce one
 *    cache line between them.
 */
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include "pod.bpf.h"

#define MAX_PODS 1024 /* headroom over maxPods (OpenShift supports up to 500) */
#define NUM_BUCKETS 4 /* <=1ms, <=10ms, catch-all, sum */
#define POD_T1_US 1000
#define POD_T2_US 10000

struct hist_key {
    struct pod_uid pod;
    u64 bucket;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, MAX_PODS * NUM_BUCKETS);
    __type(key, struct hist_key);
    __type(value, u64);
} pod_runqueue_latency_seconds SEC(".maps");

/* all tasks on the node (pods, services, kernel threads) — full distribution */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, NODE_HIST_SLOTS + 1);
    __type(key, u32);
    __type(value, u64);
} node_runqueue_latency_seconds SEC(".maps");

SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
    /* Set by sched_info_enqueue() on wakeup or on preemption while runnable,
     * cleared by sched_info_arrive() just after this tracepoint. 0 = idle task. */
    u64 queued = next->sched_info.last_queued;
    if (!queued) {
        return 0;
    }

    /* rq_clock() of the CPU next is about to run on — the clock last_queued uses */
    u64 now = next->se.cfs_rq->rq->clock;
    if (now <= queued) {
        return 0;
    }
    u64 delta_us = (now - queued) / 1000;

    node_hist_observe(&node_runqueue_latency_seconds, delta_us);

    struct hist_key key = {};
    if (!task_to_pod_uid_btf(next, &key.pod)) {
        return 0;
    }

    key.bucket = coarse_bucket(delta_us, POD_T1_US, POD_T2_US);
    increment_map_nosync(&pod_runqueue_latency_seconds, &key, 1);
    key.bucket = SUM_KEY;
    increment_map_nosync(&pod_runqueue_latency_seconds, &key, delta_us);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
