#!/usr/bin/env python3
"""Generates the Grafana dashboard and the kernel-subsystem recording-rule expression for the Helm chart.

    python3 tools/gen_dashboard.py            # writes into charts/ebpf-pod-metrics/files/

Every pod query joins the exporter's `uid` label onto kube_pod_info, so namespace/pod/node filters live on
the right side. The subsystem regexes are shared by the dashboard and the recording rule, so they're
generated together."""
import json
import os
import sys

CHART_FILES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "charts", "ebpf-pod-metrics", "files")
DASHBOARD_OUT = os.path.join(CHART_FILES, "dashboards", "ebpf-pod-metrics.json")
RULE_OUT = os.path.join(CHART_FILES, "rules", "kernel-subsystem.promql")

DS = {"type": "prometheus", "uid": "${datasource}"}
P = "ebpf_exporter_pod_"
RI = "$__rate_interval"

JOIN = (
    ' * on (uid) group_left (namespace, pod) '
    'max by (uid, namespace, pod) (kube_pod_info{namespace=~"$namespace", pod=~"$pod", node=~"$node"})'
)


def j(expr):
    """wrap a uid-keyed expression with the pod join"""
    return f"({expr}){JOIN}"


def by_pod_rate(metric, extra=""):
    lbl = f"uid{extra}"
    return j(f"sum by ({lbl}) (rate({metric}[{RI}]))")


def pod_quantile(q, metric, extra=""):
    inner = j(f"sum by (uid, le{extra}) (rate({metric}_bucket[{RI}]))")
    return f"histogram_quantile({q}, sum by (namespace, pod, le{extra}) ({inner}))"


def pod_over(metric, le, extra="", window=RI):
    """share of a pod's observations above the coarse bucket `le` (per-pod histograms have
    thresholds, not fine buckets — sized for thousands of pods)"""
    num = j(f'sum by (uid{extra}) (rate({metric}_bucket{{le="{le}"}}[{window}]))')
    den = j(f'sum by (uid{extra}) (rate({metric}_count[{window}]))')
    return (f"(1 - sum by (namespace, pod{extra}) ({num}) / sum by (namespace, pod{extra}) ({den})) >= 0")


NRQ = "ebpf_exporter_node_runqueue_latency_seconds"
NCFS = "ebpf_exporter_node_cfs_throttled_seconds"
NIO_R = "ebpf_exporter_node_block_io_read_latency_seconds"
NIO_W = "ebpf_exporter_node_block_io_write_latency_seconds"


def node_q(q, metric, by="", window=RI):
    lbl = f"{by}, le" if by else "le"
    return f'histogram_quantile({q}, sum by ({lbl}) (rate({metric}_bucket{{node=~"$node"}}[{window}])))'


_id = [0]
panels = []
y = [0]


def nid():
    _id[0] += 1
    return _id[0]


def row(title, collapsed=False, children=None):
    p = {"type": "row", "title": title, "id": nid(), "collapsed": collapsed,
         "gridPos": {"h": 1, "w": 24, "x": 0, "y": y[0]}, "panels": []}
    y[0] += 1
    if collapsed:
        p["panels"] = children or []
    panels.append(p)
    return p


def target(expr, legend="", ref="A", fmt="time_series", instant=False):
    t = {"datasource": DS, "expr": expr, "legendFormat": legend, "refId": ref,
         "range": not instant, "instant": instant}
    if fmt != "time_series":
        t["format"] = fmt
    return t


def ts(title, targets, unit, x, w, h=8, desc="", stack=False, legend_calcs=("mean", "max"), dest=None,
       min0=True):
    p = {
        "type": "timeseries", "title": title, "id": nid(), "datasource": DS, "description": desc,
        "gridPos": {"h": h, "w": w, "x": x, "y": y[0]},
        "fieldConfig": {
            "defaults": {
                "unit": unit,
                "min": 0 if min0 else None,
                "custom": {"drawStyle": "line", "lineWidth": 1, "fillOpacity": 10 if not stack else 60,
                           "showPoints": "never", "spanNulls": True,
                           "stacking": {"mode": "normal" if stack else "none", "group": "A"}},
            },
            "overrides": [],
        },
        "options": {
            "legend": {"displayMode": "table", "placement": "right", "calcs": list(legend_calcs),
                       "sortBy": "Max", "sortDesc": True},
            "tooltip": {"mode": "multi", "sort": "desc"},
        },
        "targets": targets,
    }
    if p["fieldConfig"]["defaults"]["min"] is None:
        del p["fieldConfig"]["defaults"]["min"]
    (dest if dest is not None else panels).append(p)
    return p


def stat(title, expr, unit, x, w, h=4, desc="", thresholds=None, dest=None, color_mode="value"):
    p = {
        "type": "stat", "title": title, "id": nid(), "datasource": DS, "description": desc,
        "gridPos": {"h": h, "w": w, "x": x, "y": y[0]},
        "fieldConfig": {"defaults": {"unit": unit, "thresholds": thresholds or {
            "mode": "absolute", "steps": [{"color": "text", "value": None}]}}, "overrides": []},
        "options": {"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
                    "colorMode": color_mode, "graphMode": "area", "textMode": "value", "justifyMode": "center"},
        "targets": [target(expr, instant=True)],
    }
    (dest if dest is not None else panels).append(p)
    return p


def heatmap(title, expr, x, w, h=8, desc="", dest=None):
    p = {
        "type": "heatmap", "title": title, "id": nid(), "datasource": DS, "description": desc,
        "gridPos": {"h": h, "w": w, "x": x, "y": y[0]},
        "options": {
            "calculate": False,
            "cellGap": 1,
            "color": {"mode": "scheme", "scheme": "Oranges", "scale": "exponential", "exponent": 0.5,
                      "fill": "dark-orange", "reverse": False, "steps": 64},
            "yAxis": {"axisPlacement": "left", "unit": "s", "reverse": False},
            "rowsFrame": {"layout": "le"},
            "tooltip": {"mode": "single", "yHistogram": True, "showColorScale": True},
            "legend": {"show": True},
            "filterValues": {"le": 1e-9},
            "cellValues": {"unit": "short"},
            "exemplars": {"color": "rgba(255,0,255,0.7)"},
        },
        "fieldConfig": {"defaults": {"custom": {"scaleDistribution": {"type": "linear"}}}, "overrides": []},
        "targets": [target(expr, "{{le}}", fmt="heatmap")],
    }
    (dest if dest is not None else panels).append(p)
    return p


def table(title, expr, x, w, h=8, desc="", dest=None):
    p = {
        "type": "table", "title": title, "id": nid(), "datasource": DS, "description": desc,
        "gridPos": {"h": h, "w": w, "x": x, "y": y[0]},
        "fieldConfig": {"defaults": {"unit": "none", "decimals": 0}, "overrides": []},
        "options": {"showHeader": True, "sortBy": [{"displayName": "OOM kills", "desc": True}],
                    "footer": {"show": False}},
        "targets": [target(expr, fmt="table", instant=True)],
        "transformations": [{"id": "organize", "options": {
            "excludeByName": {"Time": True},
            "renameByName": {"Value": "OOM kills", "comm": "process"},
            "indexByName": {"namespace": 0, "pod": 1, "comm": 2, "Value": 3}}}],
    }
    (dest if dest is not None else panels).append(p)
    return p



def multi_table(title, cols, keys, x, w, h=8, desc="", sort_col=None, dest=None):
    """cols: list of (header, expr, unit, thresholds_or_None). One instant query per column,
    merged on the shared label keys."""
    targets, overrides, rename, index = [], [], {}, {}
    for i, k in enumerate(keys):
        index[k] = i
    for i, (hdr, expr, unit, thr) in enumerate(cols):
        ref = chr(ord("A") + i)
        targets.append(target(expr, ref=ref, fmt="table", instant=True))
        rename[f"Value #{ref}"] = hdr
        index[f"Value #{ref}"] = len(keys) + i
        props = [{"id": "unit", "value": unit}]
        if thr:
            props += [{"id": "thresholds", "value": thr},
                      {"id": "custom.cellOptions", "value": {"type": "color-background", "mode": "gradient"}}]
        overrides.append({"matcher": {"id": "byName", "options": hdr}, "properties": props})
    p = {
        "type": "table", "title": title, "id": nid(), "datasource": DS, "description": desc,
        "gridPos": {"h": h, "w": w, "x": x, "y": y[0]},
        "fieldConfig": {"defaults": {"decimals": 2, "custom": {"align": "auto", "filterable": True}},
                        "overrides": overrides},
        "options": {"showHeader": True, "footer": {"show": False},
                    "sortBy": [{"displayName": sort_col or cols[0][0], "desc": True}]},
        "targets": targets,
        "transformations": [
            {"id": "merge", "options": {}},
            {"id": "organize", "options": {"excludeByName": {"Time": True}, "renameByName": rename,
                                           "indexByName": index}},
        ],
    }
    (dest if dest is not None else panels).append(p)
    return p


def pct_steps(warn, crit):
    return {"mode": "absolute", "steps": [{"color": "transparent", "value": None},
                                          {"color": "orange", "value": warn}, {"color": "red", "value": crit}]}


LEG = "{{namespace}}/{{pod}}"
RQ = P + "runqueue_latency_seconds"
CFS = P + "cfs_throttled_seconds"
BIO = P + "block_io_latency_seconds"

# ── Overview ─────────────────────────────────────────────────────────────────
row("Overview")
stat("Pods observed", f"count({j(f'sum by (uid) (rate({RQ}_count[5m]))')})", "none", 0, 4,
     desc="Pods (matching the filters) whose threads were scheduled in the last 5m.")
stat("Nodes reporting", 'count(up{job="ebpf-exporter"} == 1)', "none", 4, 4,
     desc="ebpf-exporter targets currently up.")
stat("Programs detached", 'count(ebpf_exporter_ebpf_program_attached == 0) or vector(0)', "none", 8, 4,
     desc="eBPF programs that failed to attach anywhere. Should be 0 — see the Exporter health row.",
     thresholds={"mode": "absolute", "steps": [{"color": "green", "value": None}, {"color": "red", "value": 1}]},
     color_mode="background")
stat("Worst pod: CPU waits > 10 ms", f"max({pod_over(RQ, '0.01', window='5m')})", "percentunit", 12, 4,
     desc="Highest share of run-queue waits longer than 10 ms across the selected pods (last 5m).",
     thresholds={"mode": "absolute", "steps": [{"color": "green", "value": None},
                                               {"color": "orange", "value": 0.01},
                                               {"color": "red", "value": 0.05}]},
     color_mode="background")
stat("TCP retransmits / s", f"sum({by_pod_rate(P + 'tcp_retransmits_total')}) or vector(0)", "pps", 16, 4,
     desc="Total TCP retransmissions across the selected pods.")
stat("OOM kills (range)", f"sum(increase(ebpf_exporter_pod_oom_kills_total[$__range]){JOIN}) or vector(0)",
     "none", 20, 4, desc="Kernel OOM kills inside the selected pods over the dashboard time range.",
     thresholds={"mode": "absolute", "steps": [{"color": "green", "value": None}, {"color": "red", "value": 1}]},
     color_mode="background")
y[0] += 4

# ── Node CPU ─────────────────────────────────────────────────────────────────
# node-exporter on OpenShift sets instance=<node name>; copy it into `node`.
def nx(expr):
    return f'label_replace({expr}, "node", "$1", "instance", "(.*)")'

IDLE = 'node_cpu_seconds_total{mode="idle", instance=~"$node"}'
NODE_CPU_UTIL = f"1 - avg by (node) ({nx(f'rate({IDLE}[5m])')})"
NODE_CORES = f"count by (node) ({nx(IDLE)})"
NODE_LOAD = lambda n: f"max by (node) ({nx(f'node_load{n}{{instance=~\"$node\"}}')}) / {NODE_CORES}"
LIVE = 'max by (namespace, pod) (kube_pod_status_phase{phase=~"Pending|Running"} == 1)'
NODE_REQ = (f'sum by (node) (kube_pod_container_resource_requests{{resource="cpu", node=~"$node"}} '
            f'* on (namespace, pod) group_left () {LIVE}) '
            f'/ sum by (node) (kube_node_status_allocatable{{resource="cpu", node=~"$node"}})')
NODE_JOIN = ' * on (uid) group_left (node) max by (uid, node) (kube_pod_info{node=~"$node"})'
NODE_RQ_WAIT = f"sum by (node) ((sum by (uid) (rate({RQ}_sum[5m]))){NODE_JOIN})"
NODE_RQ_P99 = node_q(0.99, NRQ, by="node", window="5m")

row("Node CPU")
multi_table("Nodes — CPU utilization, load and contention", [
    ("CPU util", NODE_CPU_UTIL, "percentunit", pct_steps(0.7, 0.9)),
    ("Load1 / core", NODE_LOAD(1), "none", pct_steps(1, 2)),
    ("Load15 / core", NODE_LOAD(15), "none", pct_steps(1, 2)),
    ("CPU requested", NODE_REQ, "percentunit", pct_steps(0.8, 1)),
    ("Pods' threads waiting", NODE_RQ_WAIT, "none", pct_steps(0.5, 2)),
    ("Run-queue p99 (all tasks)", NODE_RQ_P99, "s", pct_steps(0.01, 0.05)),
    ("Cores", NODE_CORES, "none", None),
], ["node"], 0, 24, h=9,
   desc="One row per node, last 5m. Load/core > 1 means more runnable threads than CPUs. "
        "'Pods' threads waiting' and 'run-queue p99' come from eBPF and show what that load costs the pods: "
        "high load with low waits is harmless (often D-state/IO), low util with high waits points at "
        "pinning, CFS bandwidth or a few hot cores.")
y[0] += 9
p = ts("Node CPU utilization — top $topk nodes",
       [target(f"topk($topk, {NODE_CPU_UTIL.replace('[5m]', f'[{RI}]')})", "{{node}}")], "percentunit", 0, 12,
       desc="1 − idle across all cores, from node-exporter.")
p["fieldConfig"]["defaults"]["max"] = 1
p = ts("Node load1 per core — top $topk nodes",
       [target(f"topk($topk, {NODE_LOAD(1)})", "{{node}}")], "none", 12, 12,
       desc="node_load1 / CPU count. Linux load includes uninterruptible (IO) sleep, so cross-check with "
            "the run-queue panels before blaming CPU.")
p["fieldConfig"]["defaults"]["custom"]["thresholdsStyle"] = {"mode": "line+area"}
p["fieldConfig"]["defaults"]["thresholds"] = {"mode": "absolute", "steps": [
    {"color": "transparent", "value": None}, {"color": "rgba(255,120,0,0.15)", "value": 1}]}
y[0] += 8
p = ts("CPU time by mode (selected nodes)", [
    target(f'sum by (mode) (rate(node_cpu_seconds_total{{mode!="idle", instance=~"$node"}}[{RI}])) '
           f'/ scalar(count(node_cpu_seconds_total{{mode="idle", instance=~"$node"}}))', "{{mode}}")],
    "percentunit", 0, 12, stack=True, legend_calcs=("mean", "max"),
    desc="Where the busy time goes. High system/softirq points at networking or kernel work; "
         "steal at an oversubscribed hypervisor (KubeVirt workers); iowait isn't really CPU busy.")
p["fieldConfig"]["defaults"]["max"] = 1
ts("Pods' threads waiting for CPU — top $topk nodes",
   [target(f"topk($topk, {NODE_RQ_WAIT.replace('[5m]', f'[{RI}]')})", "{{node}}")], "none", 12, 12,
   desc="eBPF run-queue wait summed over every pod on the node = average number of pod threads that are "
        "runnable but not running. Rising here while CPU util is flat = contention, not lack of capacity.")
y[0] += 8

POD_SEL = 'kube_pod_info{node=~"$node", namespace=~"$namespace", pod=~"$pod"}'
POD_FILTER = f' * on (namespace, pod) group_left () max by (namespace, pod) ({POD_SEL})'
CPU_USED = (f'sum by (namespace, pod) (rate(container_cpu_usage_seconds_total{{container!="", container!="POD"}}[5m]))'
            f'{POD_FILTER}')
REQ = lambda kind: (f'sum by (namespace, pod) (kube_pod_container_resource_{kind}{{resource="cpu"}})'
                    f'{POD_FILTER}')
POD_RQ_WAIT = f"sum by (namespace, pod) ((sum by (uid) (rate({RQ}_sum[5m]))){JOIN})"
POD_RQ_OVER = pod_over(RQ, "0.001", window="5m")
POD_THR = f"sum by (namespace, pod) ((sum by (uid) (rate({CFS}_sum[5m]))){JOIN})"
# With thousands of pods in scope, keep the table to the 50 biggest consumers + 50 biggest waiters.
ROWS = f"(topk(50, {CPU_USED}) or topk(50, {POD_RQ_WAIT}))"
lim = lambda e: f"({e}) and on (namespace, pod) {ROWS}"
multi_table("Pods on selected nodes — top CPU users and top CPU waiters", [
    ("CPU used (cores)", lim(CPU_USED), "none", None),
    ("CPU request", lim(REQ("requests")), "none", None),
    ("CPU limit", lim(REQ("limits")), "none", None),
    ("Threads waiting", lim(POD_RQ_WAIT), "none", pct_steps(0.2, 1)),
    ("Waits > 1 ms", lim(POD_RQ_OVER), "percentunit", pct_steps(0.05, 0.2)),
    ("CFS throttled (s/s)", lim(POD_THR), "none", pct_steps(0.1, 0.5)),
], ["namespace", "pod"], 0, 24, h=10,
   desc="Union of the 50 pods using the most CPU and the 50 waiting the most (bounded even with thousands of pods "
        "in scope). High 'CPU used' above request = who drives the node; high 'Threads waiting' / 'Waits > 1 ms' "
        "with modest usage = who suffers. Throttled pods are capped by their own limit, not by the node.")
y[0] += 10

# ── Node CPU: who is using it (eBPF sampling) ───────────────────────────────
HZ = 49
SAMP = "ebpf_exporter_node_cpu_samples_total"
FUNC = "ebpf_exporter_node_kernel_function_samples_total"
IDLE_FN = ("(intel_idle.*|poll_idle|default_idle.*|acpi_idle.*|acpi_safe_halt|cpuidle_enter.*|mwait_idle.*|"
           ".*safe_halt|cpu_idle_poll.*|do_idle|arch_cpu_idle.*|cpu_startup_entry|amd_e400_idle|haltpoll.*)")
OWNER = lambda e: (
    'label_replace(label_replace(label_replace('
    f'{e}, "owner", "pods", "context", "pod"), '
    '"owner", "node services (non-pod processes)", "context", "system"), '
    '"owner", "kernel threads", "context", "kernel")')
SUBSYS = [  # later entries win when several match
    ("syscall entry & CPU-bug mitigations", ".*(syscall|entry_SYSCALL|exit_to_user|return_thunk|untrain_ret|srso_|retbleed|its_).*"),
    ("scheduler", ".*(schedule|sched_|pick_next|enqueue_|dequeue_|update_curr|load_balance|finish_task_switch|__switch_to|psi_).*"),
    ("irq & timers", ".*(irq|softirq|apic|hrtimer|tick_|timer_).*"),
    ("locking", ".*(spin_lock|spin_unlock|_raw_spin|queued_spin|mutex|rwsem|osq_|rwlock|_lock_|down_read|down_write|up_read|up_write).*"),
    ("memcpy/memset & user copies", ".*(memset|memcpy|memmove|copy_user|copy_to_user|copy_from_user|clear_user|rep_movs|__copy_).*"),
    ("rcu", ".*rcu_.*"),
    ("networking", ".*(tcp_|udp_|skb|__dev_|net_rx|napi|netif|ip_|ipv6_|nf_|nft_|ovs_|vxlan|geneve|sock_|inet_|mlx5|ixgbe|i40e|ice_|bnxt|virtnet|xdp|sk_alloc|sk_free|sk_clone|sk_stream).*"),
    ("filesystem", ".*(ext4_|xfs_|vfs_|dentry|d_alloc|__d_|inode|lookup_|path_|filemap|generic_file|iomap|jbd2|bh_|brelse|ovl_|fuse_|nfs_|recently_deleted|find_get_block|generic_permission|fscrypt|mark_buffer|fsnotify|iput|__fput|hash_name|folio_mark_accessed|link_path_walk|getname|filldir|readdir).*"),
    ("block IO", ".*(blk_|bio_|scsi_|nvme_|dm_|submit_bio).*"),
    ("page alloc & faults", ".*(alloc_pages|get_page_from_freelist|free_pages|free_unref|rmqueue|__free_one_page|clear_page|copy_page|page_fault|handle_mm_fault|do_anonymous_page|do_fault).*"),
    ("reclaim & compaction", ".*(shrink_|kswapd|_lru_|lru_add|lruvec|reclaim|isolate_|evict|workingset|compact|migrate_pages).*"),
    ("memcg charging", ".*(memcg|mem_cgroup|obj_cgroup|refill_stock|drain_stock|page_counter).*"),
    ("slab (SLUB)", ".*(slab|slub|kmem_cache|kmalloc|kfree|__kmem|krealloc|kvfree|kvmalloc).*"),
    ("security (SELinux/audit)", ".*(selinux|avc_|security_|audit).*"),
    ("eBPF", ".*(bpf_|bpf_prog).*"),
    ("virtualization", ".*(kvm|vmx|svm|vhost).*"),
]


def subsys(e):
    out = f'label_replace({e}, "subsystem", "other", "function", ".*")'
    for name, rx in SUBSYS:
        out = f'label_replace({out}, "subsystem", "{name}", "function", "{rx}")'
    return out


KSEL = f'node=~"$node", context=~"$kctx", function!~"{IDLE_FN}"'

BUSY_RATE = "rate(" + SAMP + '{node=~"$node", context!="idle"}[' + RI + "])"
row("Node CPU — who is using it (eBPF sampling)")
p = ts("Node CPU by owner (cores, selected nodes)", [
    target(f"sum by (owner) ({OWNER(BUSY_RATE)}) / {HZ}", "{{owner}}", "A"),
    target(f'sum(rate({FUNC}{{node=~"$node", context="idle", function!~"{IDLE_FN}"}}[{RI}])) / {HZ}',
           "interrupts on idle CPUs", "B"),
], "none", 0, 12, stack=True, legend_calcs=("mean", "max"),
   desc="Sampled at 49 Hz on every CPU. Pods vs. everything that isn't a pod: node services (kubelet, crio, "
        "ovs, NetworkManager, journald…) and kernel threads (kswapd, kworker, ksoftirqd, irq/…). Interrupt/softirq "
        "work that hits a busy CPU is charged to whatever was running there.")
ts("Top non-pod CPU consumers — top $topk (cores)",
   [target(f'topk($topk, sum by (context, name) (rate({SAMP}{{node=~"$node", context=~"system|kernel"}}[{RI}])) / {HZ})',
           "{{context}}: {{name}}")], "none", 12, 12,
   desc="system = non-pod cgroup (systemd service/scope); kernel = kernel thread, per-CPU/instance suffixes folded "
        "(kworker/3:1 → kworker, kswapd0 → kswapd).")
y[0] += 8
multi_table("Non-pod CPU by service / kernel thread (cores, last 5m)", [
    ("total", f'sum by (context, name) (rate({SAMP}{{node=~"$node", context=~"system|kernel"}}[5m])) / {HZ}', "none",
     pct_steps(0.5, 1)),
    ("user mode", f'sum by (context, name) (rate({SAMP}{{node=~"$node", context=~"system|kernel", mode="user"}}[5m])) / {HZ}',
     "none", None),
    ("kernel mode", f'sum by (context, name) (rate({SAMP}{{node=~"$node", context=~"system|kernel", mode="kernel"}}[5m])) / {HZ}',
     "none", None),
], ["context", "name"], 0, 9, h=10, sort_col="total",
   desc="High 'kernel mode' on a service usually means syscall/IO/allocation overhead it triggers — see the kernel "
        "function panels to the right.")
# Recording rule (deploy/monitoring.yaml) pre-aggregates the regex grouping once a minute;
# evaluating 17 label_replace()s over every function series per panel refresh took ~2 s at 28 nodes.
SUBSYS_RULE = "ebpf:node_kernel_subsystem_cores:rate2m"
RULE_EXPR = ("sum by (node, context, subsystem) ("
             + subsys("rate(" + FUNC + '{context!="idle"}[2m]) or rate(' + FUNC
                      + '{context="idle", function!~"' + IDLE_FN + '"}[2m])') + ") / " + str(HZ))
with open(RULE_OUT, "w") as f:
    f.write(RULE_EXPR + "\n")
p = ts("Kernel CPU by subsystem (cores) — context: $kctx", [
    target(f'sum by (subsystem) ({SUBSYS_RULE}{{node=~"$node", context=~"$kctx"}})', "{{subsystem}}")],
    "none", 9, 15, h=10, stack=True, legend_calcs=("mean", "max"),
    desc="Kernel-mode samples grouped by function-name heuristics. 'slab (SLUB)' = kmem_cache/kmalloc/kfree and the "
         "slab paths; 'memcg charging' = cgroup memory accounting (often riding on slab allocations). Use the "
         "'Kernel context' filter to see whether it happens on behalf of pods, node services or kernel threads.")
y[0] += 10
ts("Top kernel functions — top $topk (cores) — context: $kctx",
   [target(f'topk($topk, sum by (function, context) (rate({FUNC}{{{KSEL}}}[{RI}])) / {HZ})',
           "{{function}} ({{context}})")], "none", 0, 24, h=9,
   desc="Kernel functions where CPU was sampled (idle-loop functions excluded). A function under 'idle' context ran "
        "from an interrupt on an otherwise idle CPU.")
y[0] += 9

# ── CPU scheduling ───────────────────────────────────────────────────────────
row("CPU scheduling")
p = ts("CPU waits > 1 ms (share) — top $topk pods",
   [target(f"topk($topk, {pod_over(RQ, '0.001')})", LEG)], "percentunit", 0, 12,
   desc="Share of a pod's run-queue waits (runnable → on-CPU) longer than 1 ms. High with low CPU usage = noisy "
        "neighbours or CPU-pinning contention, not your limit. Per-pod data uses 1 ms / 10 ms thresholds to keep "
        "series low at thousands of pods; the full distribution is per node below.")
p["fieldConfig"]["defaults"]["max"] = 1
ts("Run-queue wait (avg runnable threads waiting) — top $topk pods",
   [target(f"topk($topk, sum by (namespace, pod) ({by_pod_rate(RQ + '_sum')}))", LEG)], "none", 12, 12,
   desc="Seconds spent waiting for a CPU per second = average number of this pod's threads sitting on a run queue. "
        "1.0 means one thread is always waiting.")
y[0] += 8
heatmap("Run-queue latency distribution (selected nodes, all tasks)",
        f'sum by (le) (rate({NRQ}_bucket{{node=~"$node"}}[{RI}]))', 0, 12,
        desc="Full distribution of run-queue waits for every task on the selected nodes (pods, services, kernel "
             "threads). exp2 buckets, 1 µs … 4.2 s.")
ts("Run-queue latency p99 per node (all tasks) — top $topk nodes", [
    target(f"topk($topk, {node_q(0.99, NRQ, by='node')})", "{{node}} p99", "A"),
], "s", 12, 12, legend_calcs=("mean", "max", "lastNotNull"),
   desc="Node-level p99 from the full exp2 histogram. Compare nodes: a high p99 here with moderate CPU util means "
        "contention on a few cores (pinning, IRQ affinity, CFS bandwidth), not node capacity.")
y[0] += 8
ts("CFS throttled time — top $topk pods",
   [target(f"topk($topk, sum by (namespace, pod) ({by_pod_rate(CFS + '_sum')}))", LEG)], "s", 0, 12,
   desc="Seconds per second that the pod's per-CPU run queues were frozen by CFS bandwidth control (cpu.max). "
        "Summed across CPUs, so it can exceed 1.")
p = ts("Throttle stalls > 10 ms (share) — top $topk pods",
   [target(f"topk($topk, {pod_over(CFS, '0.01')})", LEG)], "percentunit", 12, 12,
   desc="Share of a pod's CFS throttle stalls longer than 10 ms (the per-pod buckets are 10 ms and 80 ms of the "
        "100 ms period). cAdvisor only tells you *that* you were throttled; long stalls mean the quota runs out "
        "early in every period — latency spikes for request-serving pods.")
p["fieldConfig"]["defaults"]["max"] = 1
y[0] += 8

# ── Network ──────────────────────────────────────────────────────────────────
row("Network (TCP)")
ts("TCP retransmits / s — top $topk pods",
   [target(f"topk($topk, sum by (namespace, pod) ({by_pod_rate(P + 'tcp_retransmits_total')}))", LEG)], "pps", 0, 8,
   desc="Retransmitted segments, attributed via the socket's cgroup (works for timer/softirq-driven retransmits).")
ts("TCP RSTs sent / s — top $topk pods",
   [target(f"topk($topk, sum by (namespace, pod) ({by_pod_rate(P + 'tcp_resets_sent_total')}))", LEG)], "pps", 8, 8,
   desc="Resets sent by full sockets owned by the pod (aborts, closes with unread data). "
        "RSTs to closed ports have no owning socket and aren't counted.")
ts("TCP RSTs received / s — top $topk pods",
   [target(f"topk($topk, sum by (namespace, pod) ({by_pod_rate(P + 'tcp_resets_received_total')}))", LEG)], "pps", 16, 8,
   desc="Connection refused / peer aborts seen by the pod. Spikes usually mean a dependency restarting or a "
        "load balancer killing idle connections.")
y[0] += 8

# ── Block IO ─────────────────────────────────────────────────────────────────
row("Block IO")
LEG_OP = "{{namespace}}/{{pod}} {{operation}}"
p = ts("Block IOs > 10 ms (share) — top $topk pod/op",
   [target(f"topk($topk, {pod_over(BIO, '0.01', ', operation')})", LEG_OP)], "percentunit", 0, 8,
   desc="Share of a pod's block requests that took longer than 10 ms from allocation to completion (like iostat "
        "await, incl. IO-scheduler queueing), attributed by the bio's blkcg (buffered writeback is charged to the pod "
        "that dirtied the pages). Network/FUSE filesystems (NFS, CephFS) don't pass the block layer.")
p["fieldConfig"]["defaults"]["max"] = 1
ts("Block IOPS — top $topk pod/op",
   [target(f"topk($topk, sum by (namespace, pod, operation) ({by_pod_rate(BIO + '_count', ', operation')}))", LEG_OP)],
   "iops", 8, 8, desc="Completed block requests per second.")
ts("Block IO avg latency — top $topk pod/op",
   [target(f"topk($topk, sum by (namespace, pod, operation) ({by_pod_rate(BIO + '_sum', ', operation')}) "
           f"/ sum by (namespace, pod, operation) ({by_pod_rate(BIO + '_count', ', operation')}))", LEG_OP)],
   "s", 16, 8, desc="Mean latency (sum / count). Compare with the >10 ms share to spot tail-latency pods.")
y[0] += 8
ts("Block IO latency p99 per node — top $topk nodes", [
    target(f"topk($topk, {node_q(0.99, NIO_R, by='node')})", "{{node}} read", "A"),
    target(f"topk($topk, {node_q(0.99, NIO_W, by='node')})", "{{node}} write", "B"),
], "s", 0, 24, legend_calcs=("mean", "max", "lastNotNull"),
   desc="Full exp2 distribution over all block IO on the node (pods, services, kernel). A node-wide p99 jump that "
        "isn't in any single pod usually means the device or the storage backend, not a noisy pod.")
y[0] += 8

# ── Memory ───────────────────────────────────────────────────────────────────
row("Memory")
table("OOM kills in range",
      f"sum by (namespace, pod, comm) (increase(ebpf_exporter_pod_oom_kills_total[$__range]){JOIN}) > 0",
      0, 10, desc="Kernel OOM kills by victim process. Keyed by pod (not container), so kills survive the "
                  "container restart that follows.")
ts("OOM kills — top $topk pods",
   [target(f"topk($topk, sum by (namespace, pod) (increase(ebpf_exporter_pod_oom_kills_total[{RI}]){JOIN}))", LEG)],
   "none", 10, 14, stack=True, legend_calcs=("sum",),
   desc="OOM kills per interval. Includes kills of sidecars and child processes that don't restart the container.")
y[0] += 8

# ── Exporter health (collapsed) ──────────────────────────────────────────────
health = []
yy = y[0] + 1
y_saved = y[0]
y[0] = yy
ts("Attached programs per node", [
    target('sum by (node) (ebpf_exporter_ebpf_program_attached)', "{{node}} attached", "A"),
], "none", 0, 8, legend_calcs=("lastNotNull", "min"), dest=health,
   desc="Expected: 8 per node (runqlat 1, cfs 1, tcp 3, block 1, oom 1, cpu profile 1).")
ts("eBPF CPU cost by program", [
    target('sum by (config, program) (rate(ebpf_exporter_ebpf_program_run_time_seconds[$__rate_interval]) '
           '* on (id, instance) group_left (config, program) ebpf_exporter_ebpf_program_info)',
           "{{config}}/{{program}}", "A"),
], "percentunit", 8, 8, legend_calcs=("mean", "max"), dest=health,
   desc="CPU time spent inside the BPF programs, summed over the selected cluster (1 = one full core). "
        "Empty unless sysctl kernel.bpf_stats_enabled=1 (adds ~20ns per program run).")
ts("Exporter memory", [
    target('max by (node) (process_resident_memory_bytes{job="ebpf-exporter"})', "{{node}} RSS", "A"),
    target('sum by (node) (rate(ebpf_exporter_node_kernel_function_samples_dropped_total[$__rate_interval]))',
           "{{node}} kernel samples dropped/s", "B"),
], "bytes", 16, 8, legend_calcs=("lastNotNull", "max"), dest=health,
   desc="Exporter RSS per node, and kernel-function samples dropped because the 32k-address map is full (should stay 0)." )
y[0] = y_saved
row("Exporter health", collapsed=True, children=health)

dashboard = {
    "title": "Nodes & Pods — CPU and eBPF kernel metrics",
    "uid": "ebpf-pod-metrics",
    "description": "Node CPU utilization/load and non-pod CPU attribution (services, kernel threads, kernel functions) plus per-pod run-queue latency, CFS throttle stalls, TCP "
                   "retransmits/RSTs, block IO latency and OOM kills from ebpf_exporter, joined by pod UID.",
    "tags": ["ebpf", "kubernetes", "openshift", "pods"],
    "editable": True,
    "graphTooltip": 1,
    "refresh": "1m",
    "time": {"from": "now-3h", "to": "now"},
    "schemaVersion": 39,
    "version": 1,
    "links": [],
    "annotations": {"list": [{"builtIn": 1, "datasource": {"type": "grafana", "uid": "-- Grafana --"},
                              "enable": True, "hide": True, "iconColor": "rgba(0, 211, 255, 1)",
                              "name": "Annotations & Alerts", "type": "dashboard"}]},
    "templating": {"list": [
        {"name": "datasource", "label": "Data source", "type": "datasource", "query": "prometheus",
         "current": {}, "hide": 0, "refresh": 1, "regex": "",
         "description": "Use thanos-querier (or anything that sees both kube_pod_info and the exporter metrics)."},
        {"name": "node", "label": "Node", "type": "query", "datasource": DS,
         "query": {"query": "label_values(kube_pod_info, node)", "refId": "node"},
         "definition": "label_values(kube_pod_info, node)",
         "multi": True, "includeAll": True, "allValue": ".*", "current": {"text": "All", "value": "$__all"},
         "refresh": 2, "sort": 1, "hide": 0},
        {"name": "namespace", "label": "Namespace", "type": "query", "datasource": DS,
         "query": {"query": 'label_values(kube_pod_info{node=~"$node"}, namespace)', "refId": "namespace"},
         "definition": 'label_values(kube_pod_info{node=~"$node"}, namespace)',
         "multi": True, "includeAll": True, "allValue": ".*", "current": {"text": "All", "value": "$__all"},
         "refresh": 2, "sort": 1, "hide": 0},
        {"name": "pod", "label": "Pod", "type": "query", "datasource": DS,
         "query": {"query": 'label_values(kube_pod_info{node=~"$node", namespace=~"$namespace"}, pod)',
                   "refId": "pod"},
         "definition": 'label_values(kube_pod_info{node=~"$node", namespace=~"$namespace"}, pod)',
         "multi": True, "includeAll": True, "allValue": ".*", "current": {"text": "All", "value": "$__all"},
         "refresh": 2, "sort": 1, "hide": 0},
        {"name": "kctx", "label": "Kernel context", "type": "custom", "query": "pod,system,kernel,idle",
         "multi": True, "includeAll": True, "allValue": ".*", "current": {"text": "All", "value": "$__all"},
         "options": [], "hide": 0},
        {"name": "topk", "label": "Top N", "type": "custom", "query": "5,10,20,50",
         "current": {"text": "10", "value": "10"},
         "options": [{"text": v, "value": v, "selected": v == "10"} for v in ["5", "10", "20", "50"]],
         "multi": False, "includeAll": False, "hide": 0},
    ]},
    "panels": panels,
}

with open(DASHBOARD_OUT, "w") as f:
    json.dump(dashboard, f, indent=2)
    f.write("\n")
print("panels:", sum(1 + len(p.get("panels", [])) for p in panels))
