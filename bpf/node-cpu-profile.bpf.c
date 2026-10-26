/* SPDX-License-Identifier: MIT */
/*
 * Node CPU attribution by sampling: a CPU-clock perf event fires at 49 Hz on
 * every CPU (idle or not). Each sample is attributed to
 *   - context: pod | system (non-pod cgroup: kubelet, crio, ovs, ...) |
 *              kernel (kernel thread: kswapd, kworker, ksoftirqd, irq/...) |
 *              idle (pid 0: interrupt/softirq work landing on an idle CPU, or true idle)
 *   - name:    service cgroup or normalized kernel-thread name ("" for pods/idle)
 *   - mode:    user | kernel
 * and, for kernel-mode samples, to the kernel function that was executing
 * (decoded via /proc/kallsyms) — that's where slab/SLUB, reclaim, memcg
 * charging, lock contention and networking overhead become visible.
 *
 * rate(samples) / 49 = CPU cores.
 */
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include "pod.bpf.h"

#define SAMPLE_HZ 49
#define PF_KTHREAD 0x00200000
#define NAME_LEN 40
#define COMM_LEN 16

enum {
    CTX_IDLE = 0,
    CTX_POD = 1,
    CTX_SYSTEM = 2,
    CTX_KERNEL = 3,
};

struct sample_key {
    char name[NAME_LEN];
    u32 context;
    u32 mode;
};

struct func_key {
    u64 addr;
    u32 context;
    u32 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct sample_key);
    __type(value, u64);
} node_cpu_samples_total SEC(".maps");

/* HASH (not LRU): counters must never shrink. When full, new addresses are counted as dropped. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, struct func_key);
    __type(value, u64);
} node_kernel_function_samples_total SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} node_kernel_function_samples_dropped_total SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct sample_key);
} sample_scratch SEC(".maps");

/* Leaf cgroup to name a non-pod process by: v2 tree, or the v1 cpu hierarchy on legacy nodes. */
static __always_inline struct cgroup *leaf_cgroup(struct task_struct *task)
{
    struct css_set *cs = BPF_CORE_READ(task, cgroups);
    struct cgroup *dfl = BPF_CORE_READ(cs, dfl_cgrp);

    if (BPF_CORE_READ(dfl, level) > 0) {
        return dfl;
    }

    if (bpf_core_enum_value_exists(enum cgroup_subsys_id, cpu_cgrp_id)) {
        int cpu_id = bpf_core_enum_value(enum cgroup_subsys_id, cpu_cgrp_id);
        if (cpu_id >= 0 && cpu_id < CGROUP_SUBSYS_COUNT) {
            struct cgroup *cpu_cg = BPF_CORE_READ(cs, subsys[cpu_id], cgroup);
            if (cpu_cg && BPF_CORE_READ(cpu_cg, level) > 0) {
                return cpu_cg;
            }
        }
    }

    return dfl;
}

/* "kubelet.service" as-is; "session-42.scope" -> "session.scope"; root -> "(root)" */
static __always_inline void cgroup_name(struct cgroup *cg, struct sample_key *k)
{
    const char *kn_name = BPF_CORE_READ(cg, kn, name);
    bpf_probe_read_kernel_str(k->name, sizeof(k->name), kn_name);

    if (!k->name[0]) {
        __builtin_memcpy(k->name, "(root)", 7);
        return;
    }

    if (k->name[0] == 's' && k->name[1] == 'e' && k->name[2] == 's' && k->name[3] == 's' && k->name[4] == 'i' &&
        k->name[5] == 'o' && k->name[6] == 'n' && k->name[7] == '-') {
        __builtin_memset(k->name, 0, sizeof(k->name));
        __builtin_memcpy(k->name, "session.scope", 14);
    }
}

/*
 * kworker/12:1H -> kworker, ksoftirqd/3 -> ksoftirqd, migration/7 -> migration,
 * kswapd0 -> kswapd, scsi_eh_2 -> scsi_eh, irq/125-mlx5_comp3 -> irq/mlx5_comp
 */
static __always_inline void kthread_name(struct task_struct *task, struct sample_key *k)
{
    char comm[COMM_LEN] = {};
    BPF_CORE_READ_STR_INTO(&comm, task, comm);

    bool irq = comm[0] == 'i' && comm[1] == 'r' && comm[2] == 'q' && comm[3] == '/';
    u32 start = 0, j = 0;
    bool cut = false;

    if (irq) {
        __builtin_memcpy(k->name, "irq/", 4);
        j = 4;
        start = 4;
#pragma unroll
        for (int i = 4; i < COMM_LEN; i++) {
            if (comm[i] == '-') {
                start = i + 1;
                break;
            }
        }
    }

#pragma unroll
    for (int i = 0; i < COMM_LEN; i++) {
        if (i < start) {
            continue;
        }
        char c = comm[i];
        if (!c) {
            break;
        }
        if (!irq && (c == '/' || c == ':')) {
            cut = true;
            break;
        }
        if (irq && c == '@') {
            break;
        }
        if (j >= NAME_LEN - 1) {
            break;
        }
        k->name[j] = c;
        j++;
    }

    if (cut) {
        return;
    }

    /* per-instance suffixes: trailing digits, then a trailing '_' or '-' */
#pragma unroll
    for (int i = 0; i < COMM_LEN; i++) {
        if (j == 0 || j >= NAME_LEN) {
            break;
        }
        char c = k->name[j - 1];
        if (c < '0' || c > '9') {
            break;
        }
        j--;
        k->name[j] = 0;
    }
    if (j > 0 && j < NAME_LEN && (k->name[j - 1] == '_' || k->name[j - 1] == '-')) {
        k->name[j - 1] = 0;
    }
}

static __always_inline void count_function(u64 ip, u32 context)
{
    struct func_key fk = {
        .addr = ip,
        .context = context,
    };

    u64 *v = bpf_map_lookup_elem(&node_kernel_function_samples_total, &fk);
    if (v) {
        __sync_fetch_and_add(v, 1);
        return;
    }

    u64 one = 1;
    if (bpf_map_update_elem(&node_kernel_function_samples_total, &fk, &one, BPF_NOEXIST) == 0) {
        return;
    }

    /* lost a race with another CPU, or the map is full */
    v = bpf_map_lookup_elem(&node_kernel_function_samples_total, &fk);
    if (v) {
        __sync_fetch_and_add(v, 1);
        return;
    }

    u32 zero = 0;
    increment_map(&node_kernel_function_samples_dropped_total, &zero, 1);
}

SEC("perf_event/type=1,config=0,frequency=49") /* PERF_TYPE_SOFTWARE / PERF_COUNT_SW_CPU_CLOCK */
int on_cpu_sample(struct bpf_perf_event_data *ctx)
{
    u64 ip = PT_REGS_IP(&ctx->regs);
    u32 kernel_mode = (s64) ip < 0; /* kernel text lives in the upper canonical half */
    u32 pid = (u32) bpf_get_current_pid_tgid();
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();

    u32 zero = 0;
    struct sample_key *k = bpf_map_lookup_elem(&sample_scratch, &zero);
    if (!k) {
        return 0;
    }
    __builtin_memset(k, 0, sizeof(*k));
    k->mode = kernel_mode;

    if (pid == 0) {
        k->context = CTX_IDLE;
    } else if (BPF_CORE_READ(task, flags) & PF_KTHREAD) {
        k->context = CTX_KERNEL;
        kthread_name(task, k);
    } else {
        struct pod_uid pod = {};
        if (task_to_pod_uid(task, &pod)) {
            k->context = CTX_POD;
        } else {
            k->context = CTX_SYSTEM;
            cgroup_name(leaf_cgroup(task), k);
        }
    }

    increment_map(&node_cpu_samples_total, k, 1);

    if (kernel_mode) {
        count_function(ip, k->context);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
