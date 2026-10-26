/* SPDX-License-Identifier: MIT */
/*
 * Block IO latency per pod (coarse) and per node (full distribution), split
 * by read/write.
 *
 * One hook, no start map: the block layer already stamps every request at
 * allocation (rq->start_time_ns, the basis of iostat's await), and the bios
 * are still attached when block_rq_complete fires, so both the latency and
 * the owning cgroup (bio->bi_blkg, i.e. the pod that issued or dirtied the
 * pages — cgroup v2 writeback) are read at completion. Latency therefore
 * includes IO-scheduler queueing, like await.
 */
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include "pod.bpf.h"

#define MAX_PODS 1024
#define NUM_BUCKETS 4 /* <=1ms, <=10ms, catch-all, sum */
#define POD_T1_US 1000
#define POD_T2_US 10000

#define REQ_OP_MASK 0xff
#define REQ_OP_READ 0
#define REQ_OP_WRITE 1

struct hist_key {
    struct pod_uid pod;
    u64 op;
    u64 bucket;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, MAX_PODS * NUM_BUCKETS * 2);
    __type(key, struct hist_key);
    __type(value, u64);
} pod_block_io_latency_seconds SEC(".maps");

/* all block IO on the node — per-CPU arrays, no hashing */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, NODE_HIST_SLOTS + 1);
    __type(key, u32);
    __type(value, u64);
} node_block_io_read_latency_seconds SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, NODE_HIST_SLOTS + 1);
    __type(key, u32);
    __type(value, u64);
} node_block_io_write_latency_seconds SEC(".maps");

static __always_inline struct cgroup *rq_cgroup(struct request *rq)
{
    struct bio *bio = rq->bio;
    if (!bio) {
        return NULL;
    }
    if (!bpf_core_field_exists(bio->bi_blkg)) {
        return NULL;
    }
    struct blkcg_gq *blkg = bio->bi_blkg;
    if (!blkg) {
        return NULL;
    }
    return blkg->blkcg->css.cgroup;
}

SEC("tp_btf/block_rq_complete")
int BPF_PROG(block_rq_complete, struct request *rq)
{
    u64 op = rq->cmd_flags & REQ_OP_MASK;
    if (op != REQ_OP_READ && op != REQ_OP_WRITE) {
        return 0;
    }

    u64 start = rq->start_time_ns;
    u64 now = bpf_ktime_get_ns();
    if (!start || now <= start) {
        return 0; /* queue without IO accounting: no timestamp */
    }
    u64 delta_us = (now - start) / 1000;

    if (op == REQ_OP_READ) {
        node_hist_observe(&node_block_io_read_latency_seconds, delta_us);
    } else {
        node_hist_observe(&node_block_io_write_latency_seconds, delta_us);
    }

    struct hist_key key = { .op = op };
    if (!cgroup_to_pod_uid_btf(rq_cgroup(rq), &key.pod)) {
        return 0;
    }

    key.bucket = coarse_bucket(delta_us, POD_T1_US, POD_T2_US);
    increment_map_nosync(&pod_block_io_latency_seconds, &key, 1);
    key.bucket = SUM_KEY;
    increment_map_nosync(&pod_block_io_latency_seconds, &key, delta_us);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
