/* SPDX-License-Identifier: MIT */
/*
 * Per-pod TCP health: retransmits, RSTs sent and RSTs received.
 * Attribution uses the socket's cgroup (sk_cgrp_data), not the current task,
 * so retransmits fired from timers/softirq still land on the owning pod.
 */
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include "pod.bpf.h"

#define MAX_PODS 2048

#define TCP_TIME_WAIT 6
#define TCP_NEW_SYN_RECV 12

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_PODS);
    __type(key, struct pod_uid);
    __type(value, u64);
} pod_tcp_retransmits_total SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_PODS);
    __type(key, struct pod_uid);
    __type(value, u64);
} pod_tcp_resets_sent_total SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_PODS);
    __type(key, struct pod_uid);
    __type(value, u64);
} pod_tcp_resets_received_total SEC(".maps");

/* v5.15+ layout: struct sock_cgroup_data { struct cgroup *cgroup; ... } */
struct sock_cgroup_data___new {
    struct cgroup *cgroup;
} __attribute__((preserve_access_index));

struct sock___new {
    struct sock_cgroup_data___new sk_cgrp_data;
} __attribute__((preserve_access_index));

/* pre-v5.15 layout: union with u64 val holding the cgroup pointer (bit 0 = v1 data mode) */
struct sock_cgroup_data___old {
    u64 val;
} __attribute__((preserve_access_index));

struct sock___old {
    struct sock_cgroup_data___old sk_cgrp_data;
} __attribute__((preserve_access_index));

static __always_inline struct cgroup *sk_cgroup(const struct sock *sk)
{
    struct sock___new *sn = (void *) sk;

    if (bpf_core_field_exists(sn->sk_cgrp_data.cgroup)) {
        return BPF_CORE_READ(sn, sk_cgrp_data.cgroup);
    }

    struct sock___old *so = (void *) sk;
    u64 v = BPF_CORE_READ(so, sk_cgrp_data.val);
    if (v & 1) {
        return NULL;
    }
    return (struct cgroup *) v;
}

static __always_inline int count_for_sock(void *map, const struct sock *sk)
{
    if (!sk) {
        return 0;
    }

    /* request/timewait minisocks don't carry sk_cgrp_data */
    u8 state = BPF_CORE_READ(sk, __sk_common.skc_state);
    if (state == TCP_TIME_WAIT || state == TCP_NEW_SYN_RECV) {
        return 0;
    }

    struct pod_uid key = {};
    if (!cgroup_to_pod_uid(sk_cgroup(sk), &key)) {
        return 0;
    }

    increment_map(map, &key, 1);
    return 0;
}

SEC("tp_btf/tcp_retransmit_skb")
int BPF_PROG(tcp_retransmit_skb, const struct sock *sk)
{
    return count_for_sock(&pod_tcp_retransmits_total, sk);
}

SEC("tp_btf/tcp_send_reset")
int BPF_PROG(tcp_send_reset, const struct sock *sk)
{
    return count_for_sock(&pod_tcp_resets_sent_total, sk);
}

SEC("tp_btf/tcp_receive_reset")
int BPF_PROG(tcp_receive_reset, struct sock *sk)
{
    return count_for_sock(&pod_tcp_resets_received_total, sk);
}

char LICENSE[] SEC("license") = "GPL";
