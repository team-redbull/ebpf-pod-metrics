/* SPDX-License-Identifier: MIT */
/*
 * Shared helpers: resolve any cgroup (container scope, conmon scope, nested
 * "container" sub-cgroup, or the pod slice itself) to the owning Kubernetes
 * pod UID by walking up the cgroup v2 hierarchy until a pod slice is found.
 *
 * systemd cgroup driver layouts (OpenShift / CRI-O):
 *   kubepods.slice/kubepods-pod<uid>.slice/crio-<id>.scope                          (Guaranteed)
 *   kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod<uid>.slice/...   (Burstable)
 *   kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod<uid>.slice/... (BestEffort)
 *
 * systemd escapes '-' in the UID as '_'; we convert back so the label matches
 * kube_pod_info{uid} exactly. Results (including "not a pod") are cached per
 * cgroup id, so the hot path is a single hash lookup.
 */
#ifndef __POD_BPF_H
#define __POD_BPF_H

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "maps.bpf.h"

#define POD_UID_LEN 36
#define POD_UID_SIZE 40 /* 36 chars + NUL padding, keeps 8-byte alignment */
#define CGROUP_NAME_BUF 128
#define MAX_CGROUP_WALK 6

/* "kubepods-pod" + uid + ".slice" = 54 chars; "kubepods-besteffort-pod" + uid + ".slice" = 65 */
#define POD_SLICE_MIN_LEN 54
#define POD_SLICE_MAX_LEN 72

/*
 * Histogram layout, sized for fleets with thousands of pods:
 *  - per pod: coarse fixed buckets (two thresholds + a catch-all) -> 6 series per
 *    pod per metric: share above each threshold, plus sum/count for averages;
 *  - per node: full exp2 distribution (1us .. ~4.2s, 23 buckets), once per node.
 */
#define MAX_BUCKET_US (1ULL << 22) /* catch-all bucket for per-pod histograms (~4.2s) */
#define SUM_KEY (MAX_BUCKET_US + 1)
#define NODE_HIST_SLOTS 23         /* exp2 slots 0..22; key 23 holds the sum */

struct pod_uid {
    char uid[POD_UID_SIZE];
};

struct name_buf {
    char s[CGROUP_NAME_BUF];
};

/* cgroup ids are only unique within one hierarchy (v1 has one per controller) */
struct cg_key {
    u64 id;
    u32 hierarchy;
    u32 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384); /* ~500 pods x (slice + containers + conmon) + system */
    __type(key, struct cg_key);
    __type(value, struct pod_uid);
} pod_uid_cache SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct name_buf);
} cgroup_name_scratch SEC(".maps");

static __always_inline int parse_pod_slice(const char *kn_name, struct pod_uid *out)
{
    u32 zero = 0;
    struct name_buf *b = bpf_map_lookup_elem(&cgroup_name_scratch, &zero);
    if (!b) {
        return 0;
    }

    long len = bpf_probe_read_kernel_str(b->s, sizeof(b->s), kn_name);
    /* len includes the trailing NUL */
    if (len < POD_SLICE_MIN_LEN + 1 || len > POD_SLICE_MAX_LEN + 1) {
        return 0;
    }

    if (b->s[0] != 'k' || b->s[1] != 'u' || b->s[2] != 'b' || b->s[3] != 'e' || b->s[4] != 'p' || b->s[5] != 'o' ||
        b->s[6] != 'd' || b->s[7] != 's' || b->s[8] != '-') {
        return 0;
    }

    u32 end = (u32) len - 1; /* strlen */
    u32 sfx = end - 6;       /* start of ".slice" */
    u32 off = sfx - POD_UID_LEN;

    /* keep the verifier happy: bounded indexes into the scratch buffer */
    if (sfx > CGROUP_NAME_BUF - 7 || off < 3 || off > CGROUP_NAME_BUF - POD_UID_LEN - 1) {
        return 0;
    }

    if (b->s[sfx] != '.' || b->s[sfx + 1] != 's' || b->s[sfx + 2] != 'l' || b->s[sfx + 3] != 'i' ||
        b->s[sfx + 4] != 'c' || b->s[sfx + 5] != 'e') {
        return 0;
    }

    if (b->s[off - 3] != 'p' || b->s[off - 2] != 'o' || b->s[off - 1] != 'd') {
        return 0;
    }

#pragma unroll
    for (int i = 0; i < POD_UID_LEN; i++) {
        char c = b->s[off + i];
        out->uid[i] = c == '_' ? '-' : c;
    }

    return 1;
}

/* Returns 1 and fills *out if cg belongs to a pod, 0 otherwise. */
static __always_inline int cgroup_to_pod_uid(struct cgroup *cg, struct pod_uid *out)
{
    if (!cg) {
        return 0;
    }

    struct cg_key id = {
        .id = BPF_CORE_READ(cg, kn, id),
        .hierarchy = BPF_CORE_READ(cg, root, hierarchy_id),
    };
    struct pod_uid *cached = bpf_map_lookup_elem(&pod_uid_cache, &id);
    if (cached) {
        if (!cached->uid[0]) {
            return 0;
        }
        __builtin_memcpy(out, cached, sizeof(*out));
        return 1;
    }

    struct pod_uid res = {};
    struct cgroup *cur = cg;

    for (int i = 0; i < MAX_CGROUP_WALK; i++) {
        if (!cur) {
            break;
        }
        const char *name = BPF_CORE_READ(cur, kn, name);
        if (parse_pod_slice(name, &res)) {
            break;
        }
        cur = BPF_CORE_READ(cur, self.parent, cgroup);
    }

    /* cache negative results too, so system.slice etc. stay cheap */
    bpf_map_update_elem(&pod_uid_cache, &id, &res, BPF_ANY);

    if (!res.uid[0]) {
        return 0;
    }

    __builtin_memcpy(out, &res, sizeof(res));
    return 1;
}

/*
 * Resolve via the task's cpu-controller cgroup first: on cgroup v1 (OpenShift
 * clusters upgraded from <= 4.13 keep v1) that's the v1 cpu hierarchy, where
 * kubepods slices live; on v2 it's the nearest v2 ancestor with cpu enabled.
 * Fall back to the default (v2) hierarchy if that didn't land in a pod.
 */
static __always_inline int task_to_pod_uid(struct task_struct *task, struct pod_uid *out)
{
    struct css_set *cs = BPF_CORE_READ(task, cgroups);
    struct cgroup *dfl = BPF_CORE_READ(cs, dfl_cgrp);
    struct cgroup *cpu_cg = NULL;

    if (bpf_core_enum_value_exists(enum cgroup_subsys_id, cpu_cgrp_id)) {
        int cpu_id = bpf_core_enum_value(enum cgroup_subsys_id, cpu_cgrp_id);
        if (cpu_id >= 0 && cpu_id < CGROUP_SUBSYS_COUNT) {
            struct cgroup_subsys_state *css = BPF_CORE_READ(cs, subsys[cpu_id]);
            cpu_cg = BPF_CORE_READ(css, cgroup);
        }
    }

    if (cpu_cg && cgroup_to_pod_uid(cpu_cg, out)) {
        return 1;
    }
    if (dfl == cpu_cg) {
        return 0;
    }
    return cgroup_to_pod_uid(dfl, out);
}

/*
 * Fast path for BTF-typed pointers (tp_btf / fentry arguments): plain loads
 * instead of bpf_probe_read_kernel() helper calls. Used on the scheduler hot
 * path. Falls back to the generic walk on a cache miss or on cgroup v1.
 */
static __always_inline int cgroup_to_pod_uid_btf(struct cgroup *cg, struct pod_uid *out)
{
    if (!cg) {
        return 0;
    }

    struct cg_key id = {
        .id = cg->kn->id,
        .hierarchy = cg->root->hierarchy_id,
    };
    struct pod_uid *cached = bpf_map_lookup_elem(&pod_uid_cache, &id);
    if (cached) {
        if (!cached->uid[0]) {
            return 0;
        }
        __builtin_memcpy(out, cached, sizeof(*out));
        return 1;
    }

    return cgroup_to_pod_uid(cg, out);
}

static __always_inline int task_to_pod_uid_btf(struct task_struct *task, struct pod_uid *out)
{
    struct cgroup *dfl = task->cgroups->dfl_cgrp;

    /* cgroup v2 (or a v2 placement on hybrid): the default hierarchy decides */
    if (dfl && dfl->level > 0) {
        return cgroup_to_pod_uid_btf(dfl, out);
    }

    /* cgroup v1 legacy: everything sits in the v2 root, use the cpu hierarchy */
    return task_to_pod_uid(task, out);
}

/* Per-pod coarse bucket: <= t1, <= t2, or the catch-all. Values in microseconds. */
static __always_inline u64 coarse_bucket(u64 us, u64 t1, u64 t2)
{
    if (us <= t1) {
        return t1;
    }
    if (us <= t2) {
        return t2;
    }
    return MAX_BUCKET_US;
}

static __always_inline u32 node_slot(u64 us)
{
    u64 slot = log2l_histogram(us);
    if (slot >= NODE_HIST_SLOTS) {
        slot = NODE_HIST_SLOTS - 1;
    }
    return (u32) slot;
}

/* Node-wide exp2 histogram in a per-CPU array: no hashing, no atomics. */
static __always_inline void node_hist_observe(void *map, u64 us)
{
    u32 slot = node_slot(us);
    u64 *v = bpf_map_lookup_elem(map, &slot);
    if (v) {
        *v += 1;
    }
    u32 sum = NODE_HIST_SLOTS;
    v = bpf_map_lookup_elem(map, &sum);
    if (v) {
        *v += us;
    }
}

#endif /* __POD_BPF_H */
