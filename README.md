# ebpf-pod-metrics

Per-pod and per-node kernel metrics for OpenShift from [cloudflare/ebpf_exporter](https://github.com/cloudflare/ebpf_exporter),
plus a Grafana dashboard. Things cAdvisor and node-exporter can't see.

**Full documentation:** [docs/ebpf-pod-metrics-guide.md](docs/ebpf-pod-metrics-guide.md) (architecture, metrics,
dashboard guide, installation, configuration, rollout runbook, safety, capacity, troubleshooting).

What it measures:

| Metric (prefix `ebpf_exporter_`) | Type | Labels | What it answers |
|---|---|---|---|
| `pod_runqueue_latency_seconds` | histogram (≤1 ms, ≤10 ms) | `uid` | How long the pod's threads wait for a CPU (noisy neighbours, CPU contention below the limit). Read from the scheduler's own `sched_info` stamps — one hook, no wakeup tracing |
| `node_runqueue_latency_seconds` | histogram (exp2, 1 µs–4 s) | — | Same, full distribution over every task on the node |
| `pod_cfs_throttled_seconds` | histogram (≤10 ms, ≤80 ms) | `uid` | How long each CFS throttle stall lasts, not just *that* it happened |
| `node_cfs_throttled_seconds` | histogram (exp2) | — | Full stall distribution per node |
| `pod_tcp_retransmits_total` | counter | `uid` | Retransmits, attributed via the socket's cgroup |
| `pod_tcp_resets_sent_total` / `_received_total` | counter | `uid` | RSTs out / in |
| `pod_block_io_latency_seconds` | histogram (≤1 ms, ≤10 ms) | `uid`, `operation` | Block read/write latency (request alloc → complete, like iostat await) charged to the pod, incl. writeback |
| `node_block_io_{read,write}_latency_seconds` | histogram (exp2) | — | Full distribution over all block IO on the node |
| `pod_oom_kills_total` | counter | `uid`, `comm` | Kernel OOM kills with the victim process name |
| `node_cpu_samples_total` | counter | `context`, `name`, `mode` | Who uses node CPU: pods vs. node services (`kubelet.service`, `crio.service`, `ovs-vswitchd.service`…) vs. kernel threads (`kswapd`, `kworker`, `ksoftirqd`, `irq/mlx5_comp`…), user vs. kernel mode. 49 Hz sampling; `rate/49` = cores |
| `node_kernel_function_samples_total` | counter | `function`, `context` | Which kernel functions burn CPU (SLUB `kmem_cache_*`/`kfree`, memcg charging, reclaim, locks, networking…) and on whose behalf |

The dashboard also has a **Node CPU** section built on node-exporter + KSM + cAdvisor: utilization, load1/load15 per
core, CPU mode split, requested vs. allocatable, and a per-pod "CPU used vs. CPU waited" table — next to the eBPF
run-queue numbers, so you can tell real saturation from contention. A second section attributes node CPU to
non-pod owners and groups kernel time into subsystems (slab, memcg, reclaim, locking, filesystem, networking, …).

Histograms are split for scale: **per pod**, two thresholds plus sum/count (6 series per pod per histogram — enough
for "share of waits over 1 ms / 10 ms" and averages, which is what you rank and alert on); **per node**, the full
exp2 distribution once. See [Scale](#scale-8000-pods--28-nodes) for the numbers.

## How pod attribution works

Every program resolves the cgroup of the relevant task / socket / bio / cfs_rq **in the kernel** by walking up the
cgroup v2 tree to the `kubepods-…-pod<uid>.slice`, converts systemd's `_` back to `-`, and caches the result per
cgroup id. So:

- the label is the real pod UID → joins directly onto `kube_pod_info{uid}`;
- container restarts don't lose data (keyed by pod, not container);
- non-pod cgroups (`system.slice`, kernel threads) are dropped in-kernel;
- no host mounts, no `hostPID`, no cgroup path decoding in userspace.

Works on cgroup v1 and v2 with the systemd cgroup driver (OpenShift default). Tasks are resolved through
their cpu-controller cgroup first, then the v2 tree; CFS and block IO resolve through their own controller's
cgroup, so all of those work on either mode. **TCP metrics need cgroup v2** (socket cgroup is v2-only).

## OpenShift 4.16 notes

- RHCOS 4.16 = RHEL 9.4, kernel `5.14.0-427.*`, BTF enabled. The CO-RE fallbacks in the code cover this kernel's
  layouts (`task_struct::__state`, single-arg `block_rq_issue`, either `sock_cgroup_data` layout).
- cgroup mode: new 4.14+ installs default to v2; clusters upgraded from ≤ 4.13 usually stay on v1. Check with
  `oc debug node/<node> -- chroot /host stat -fc %T /sys/fs/cgroup` (`cgroup2fs` = v2, `tmpfs` = v1).
- Kernel 5.14 has no fanotify support for cgroupfs, so the exporter uses its walker regardless of capabilities.
  The missing `DAC_READ_SEARCH` only matters once you move to a ≥ 6.6 kernel (RHEL 10-based RHCOS).
- `openshift.io/required-scc` (used to pin the SCC) is honoured from 4.14 onward.
- Before rolling to the fleet, run a one-off check on a node:
  ```
  oc -n ebpf-exporter debug ds/ebpf-exporter -- /ebpf_exporter --config.dir=/etc/ebpf-pod-metrics \
    --config.names=node-cpu-profile,pod-bio-latency,pod-cfs-throttling,pod-oomkill,pod-runqlat,pod-tcp \
    --config.check --config.strict
  ```
  This runs the 5.14 verifier against all six objects (`helm install` prints the exact command for your enabled
  programs); the test sandbox only had a 6.18 kernel.

## Layout

```
charts/ebpf-pod-metrics/      Helm chart
  values.yaml                 all knobs, commented; values.schema.json rejects typos
  files/programs/             prebuilt CO-RE objects (*.bpf.o) + their ebpf_exporter configs (*.yaml)
  files/dashboards/           Grafana dashboard JSON
  files/rules/                kernel-subsystem recording rule (generated with the dashboard)
  templates/                  SCC, RBAC, programs ConfigMap, DaemonSet, Service, ServiceMonitor,
                              PrometheusRules, optional dashboard ConfigMap / GrafanaDashboard
bpf/                          C sources + Makefile (builds into files/programs/)
tools/gen_dashboard.py        regenerates the dashboard and the recording rule
docs/                         design & operations guide (+ architecture.svg)
```

## Deploy

Prerequisites: user-workload monitoring enabled (`enableUserWorkload: true` in `cluster-monitoring-config`), the
image mirrored for air-gapped clusters, and a namespace that allows the privileged PSA level (the chart doesn't
create it — Helm stores its release in that namespace, so it must exist first).

```bash
oc image mirror ghcr.io/cloudflare/ebpf_exporter:v2.5.1 registry.internal:5000/cloudflare/ebpf_exporter:v2.5.1

oc create namespace ebpf-exporter
oc label namespace ebpf-exporter pod-security.kubernetes.io/enforce=privileged \
  pod-security.kubernetes.io/audit=privileged pod-security.kubernetes.io/warn=privileged \
  security.openshift.io/scc.podSecurityLabelSync=false

helm install ebpf-exporter charts/ebpf-pod-metrics -n ebpf-exporter \
  --set image.registry=registry.internal:5000
```

Nothing runs yet: label nodes `ebpf-exporter.io/enabled=true` to opt them in (see the rollout runbook below; the
install NOTES print the pre-flight and kill-switch commands). Upgrades: `helm upgrade ebpf-exporter
charts/ebpf-pod-metrics -n ebpf-exporter --reuse-values`.

Check: `oc -n ebpf-exporter logs ds/ebpf-exporter` should end with `Started with 6 programs` and
`ebpf_exporter_ebpf_program_attached` should be 1 for all 8 programs on every node.

### ArgoCD (OpenShift GitOps)

Point an Application at the chart directory; ArgoCD renders it with `helm template`. One Application per cluster,
from whichever ArgoCD manages that cluster (e.g. the MCE's ArgoCD for its hosted clusters):

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: ebpf-pod-metrics
  namespace: openshift-gitops
spec:
  project: default
  source:
    repoURL: https://git.internal/platform/ebpf-pod-metrics.git
    targetRevision: main
    path: charts/ebpf-pod-metrics
    helm:
      valuesObject:
        image:
          registry: registry.internal:5000
  destination:
    server: https://kubernetes.default.svc   # or the target cluster's API
    namespace: ebpf-exporter
  syncPolicy:
    automated: { prune: true, selfHeal: true }
    syncOptions: [CreateNamespace=true]
    managedNamespaceMetadata:
      labels:
        pod-security.kubernetes.io/enforce: privileged
        pod-security.kubernetes.io/audit: privileged
        pod-security.kubernetes.io/warn: privileged
        security.openshift.io/scc.podSecurityLabelSync: "false"
```

- The application controller needs RBAC for the cluster-scoped `SecurityContextConstraints` and `ClusterRole`
  (or set `scc.create=false` and `scc.name` to an SCC your platform team manages).
- The programs ConfigMap is ~600 KiB. Client-side apply would copy it into the
  `kubectl.kubernetes.io/last-applied-configuration` annotation and fail on the 256 KiB annotation limit, so it
  carries `argocd.argoproj.io/sync-options: ServerSideApply=true`. If you render and apply by hand, use
  `helm template … | oc apply --server-side -f -`.
- Air-gapped chart distribution: the git path above, or `helm package charts/ebpf-pod-metrics` and
  `helm push ebpf-pod-metrics-0.1.0.tgz oci://registry.internal/charts`.

### Main values

| Value | Default | |
|---|---|---|
| `image.registry` / `repository` / `tag` / `digest` | `ghcr.io` / `cloudflare/ebpf_exporter` / `v2.5.1` / — | digest wins over tag |
| `programs.<name>.enabled` | all `true` | `pod-runqlat`, `pod-cfs-throttling`, `pod-tcp`, `pod-bio-latency`, `pod-oomkill`, `node-cpu-profile`; capabilities follow (no `SYSLOG` without `node-cpu-profile`) |
| `nodeSelector` | `ebpf-exporter.io/enabled: "true"` | per-node opt-in |
| `resources` | 50m / 128Mi request, 500m / 256Mi limit | BPF maps are charged to the memory limit |
| `serviceMonitor.sampleLimit` | `30000` | per-node scrape guard |
| `serviceMonitor.dropKernelFunctions` | `false` | drops a third of all series (see Scale) |
| `prometheusRule.recordingRules` / `alerts.enabled` | `true` / `true` | |
| `scc.create` / `scc.name` | `true` / — | bring your own SCC |
| `dashboard.configMap.enabled` | `false` | for a Grafana sidecar (`grafana_dashboard: "1"`) |
| `dashboard.grafanaOperator.enabled` | `false` | `GrafanaDashboard` CR, grafana-operator v5 |

The dashboard's data source must see **both** the exporter metrics and `kube_pod_info` — use `thanos-querier`
(port 9091), not a single Prometheus. Without either dashboard option, import
`charts/ebpf-pod-metrics/files/dashboards/ebpf-pod-metrics.json`.

## Scale: 8000 pods / 28 nodes

Tested against a synthetic cluster with exactly that shape: 28 exporter targets serving this repo's series layout
(~286 pods per node; 30% throttled, 70% doing block IO, 20% with TCP events; ~1500 distinct kernel functions per
node), KSM + cAdvisor for 8000 pods, node-exporter CPU metrics for 64 CPUs per node, scraped by Prometheus 3.5.

| | series |
|---|---|
| per-pod eBPF metrics (8000 pods, ~17 per pod on average, ≤ 33 worst case) | ~134k |
| per-node: full histograms, CPU owners, exporter self-metrics (28 nodes) | ~5k |
| `node_kernel_function_samples_total` (function × context, 28 nodes) | ~70k |
| **total from ebpf-exporter** | **~209k** |

The first layout (12 fine buckets per pod per histogram) would have been ~63 series per pod, ~500k for the pods alone.

Every dashboard query was run instant and as a 5-minute range against that Prometheus: no errors; tables stay
bounded (the per-pod table is the top 50 CPU users ∪ top 50 waiters, not 8000 rows); most panels answer in
< 0.5 s; the heaviest per-pod range queries (block IO share/avg, CPU waits > 1 ms) took 1–3.4 s on the 2-CPU
test box while the recording rule was evaluating alongside — a real Prometheus/Thanos querier will do better. The kernel-subsystem panel needed 2.2 s as a raw query, so it now
reads the `ebpf:node_kernel_subsystem_cores:rate2m` recording rule (252 series, ~2 ms per panel load); the rule
itself evaluates once a minute in the user-workload Prometheus (`leaf-prometheus` scope).

**Budget for user-workload Prometheus:** plan on ~200–250k extra active series per replica for this cluster and size
UWM memory accordingly (in the test, Prometheus held all ~263k series of the synthetic cluster in ~540 MiB RSS shortly
after start; steady state with retention will be higher).

**If that's more than you want**, the biggest single lever is the kernel-function metric (a third of the series):
`--set serviceMonitor.dropKernelFunctions=true` drops it at scrape time and skips its recording rule. The "Top
kernel functions" and "Kernel CPU by subsystem" panels go empty; "Node CPU by owner" and "Top non-pod CPU consumers"
keep working. Next levers, in order: drop the per-pod block IO series and keep the node histograms
(`serviceMonitor.metricRelabelings` with `regex: ebpf_exporter_pod_block_io_latency_seconds.*`, ~65k), or
`programs.pod-cfs-throttling.enabled=false`.

**Disk** (measured from real TSDB blocks built with this exporter's series layout): ~2.2–3.2 GB per day of
retention per Prometheus replica with all series, ~1.4–2.1 GB without kernel functions, plus ~0.65 GB of WAL/head.
User-workload Prometheus defaults to 24 h retention and runs 2 replicas.

## Safety & overhead — why this won't hurt the node, the workloads or the API

### What the programs can and can't do
- **Read-only tracing.** Only `tp_btf`/`fentry`/`kprobe` tracing hooks and a 49 Hz perf sampler. No XDP/tc
  (not in the OVN datapath), no LSM, no `override_return`, no `probe_write_user`: they cannot drop packets, change
  scheduling decisions, block syscalls or modify memory.
- **Verifier-bounded.** Every program is proven by the kernel to terminate and to only read memory safely
  before it loads. If the RHCOS verifier rejects one, the exporter fails to start — the node is untouched.
- **No allocation on hot paths.** All maps are preallocated; nothing allocates under the runqueue lock.
- **Nothing persists.** Programs aren't pinned; they live only as long as the exporter process. Tested: after
  `kill -9` the system-wide BPF program count went from 7 back to 0 immediately.

### Measured cost (exporter v2.5.1, 6.18 kernel VM, JIT on, `kernel.bpf_stats_enabled=1`)

| Hook | Fires on | Avg cost |
|---|---|---|
| `pod-runqlat` `sched_switch` (pod + node histograms) | every context switch | **86 ns** |
| `pod-bio-latency` `block_rq_complete` (single hook) | every block IO | 319 ns |
| `node-cpu-profile` sampler | 49×/s per CPU | ~4.5 µs → ~0.02% of each CPU |
| TCP, OOM, CFS-unthrottle hooks | retransmits / RSTs / OOM kills / throttle events | rare |

Worst case A/B (two processes ping-ponging a byte, a context switch on every hop — nothing real is this
switch-bound): **+7%** round-trip time on one CPU, **+2.6%** across CPUs (inside run-to-run noise).
In node terms: 100k switches/s ≈ 8 ms of CPU per second ≈ 0.8% of *one* core, ≈ 0.01% of a 64-core node, and
+86 ns on a ~2–3 µs context switch. API request latency is in milliseconds; it doesn't register.

How it got there: the first cut cost 421 ns + 111 ns per switch/wakeup, and ~1.35 µs per block IO. Block IO now reads
the request's own allocation stamp (`rq->start_time_ns`) and the still-attached bio's cgroup at completion — one
hook, no start map. The runqueue program now reads the
kernel's own `sched_info.last_queued` stamp (the accounting behind `/proc/<pid>/schedstat`) instead of hooking
wakeups and keeping a timestamp map, uses direct BTF loads instead of `bpf_probe_read`, and per-CPU counters.

### Memory
~13 MiB of BPF maps plus ~0.1 MiB per CPU (≈25 MiB on a 128-CPU node), sized for 1024 pods per node (headroom
over a raised `maxPods`). BPF map memory is charged to the exporter's own cgroup on RHEL 9, so the 256 Mi limit
bounds it: if it can't fit, the exporter fails to start rather than eating node memory. Burstable QoS, so under
node memory pressure it's evicted before Guaranteed workloads.

### Scheduling & API server
- **No priority class.** A high-priority DaemonSet pod would preempt (evict) workload pods on a full node to get
  scheduled. At priority 0 it simply stays Pending.
- **Zero API calls.** `automountServiceAccountToken: false` — the exporter has no token and never talks to the
  apiserver. Prometheus scrapes the pod directly.
- **Immutable ConfigMap.** Content-addressed name (hash of the enabled objects and configs) and `immutable: true`,
  so kubelets don't hold a watch on it; any program change gets a new name and rolls the DaemonSet.
- **Prometheus guard.** ServiceMonitor `spec.sampleLimit: 30000` per node (~7.5k at 286 pods/node, ~13k at 500). A runaway node fails its scrape and fires
  `EbpfExporterDown` instead of flooding the TSDB.
- CPU limit 500m bounds the exporter process (scrape decoding). In-kernel BPF time is charged to the traced
  tasks, which is why it's measured separately below.

### Rollout runbook
1. **Pre-flight** on one node (5.14 verifier): the `--config.check --config.strict` command above.
2. **Canary.** Nothing runs until a node is labeled. Pick one non-critical worker:
   ```
   oc label node <node> ebpf-exporter.io/enabled=true
   oc debug node/<node> -- chroot /host sysctl -w kernel.bpf_stats_enabled=1   # not persistent; reboot resets it
   ```
   Watch for 24 h: dashboard "Exporter health → eBPF CPU cost by program" (real per-hook cost on your hardware),
   `EbpfExporterHighOverhead` (fires above 5% of a core), exporter memory, and p99 of the workloads on that node
   against a neighbour. Then `sysctl -w kernel.bpf_stats_enabled=0` (stats themselves cost ~20 ns per run).
3. **Widen in waves** — e.g. one NodePool / MachineConfigPool at a time; management-cluster nodes that host
   HyperShift control planes (kube-apiserver, etcd) last.
4. **Tune instead of all-or-nothing.** Each program is independent: `programs.pod-runqlat.enabled=false` (the only
   per-switch hook) or `programs.node-cpu-profile.enabled=false`, and the rest keeps working.
5. **Kill switch.** `oc label node <node> ebpf-exporter.io/enabled-` (one node) or `helm uninstall` / delete the
   ArgoCD Application (all): the pod exits and every program detaches immediately.

### Residual risk, stated plainly
- These numbers are from a 6.18 VM. RHEL 9.4 / bare metal will differ — the canary with `bpf_stats_enabled` is
  how you get your real numbers before going wide.
- The eBPF subsystem itself can have kernel bugs. The hooks used here are the same ones Red Hat's supported
  `bcc-tools`/`bpftrace` use on RHEL 9, which keeps that risk low, but not zero.
- Red Hat support may ask you to remove third-party privileged agents while working a node-level case.

## Security posture

Custom SCC `ebpf-exporter`: not privileged, no host paths/PID/network. Container gets `CAP_BPF`, `CAP_PERFMON`,
`CAP_SYS_RESOURCE`, `CAP_SYSLOG`, SELinux type `spc_t` (container_t is denied `bpf()`), Unconfined seccomp, read-only
root FS, and `--capabilities.keep=cap_syslog` drops everything else right after the probes attach (SYSLOG stays so
kernel-function names can be re-resolved from `/proc/kallsyms` when modules load).

`CAP_DAC_READ_SEARCH` is deliberately not granted: on kernels ≥ 6.6 it makes ebpf_exporter v2.5.1 switch its
cgroup watcher to fanotify, which `log.Fatal`s on non-directory create events in cgroupfs (reproduced during
testing). Without it the exporter falls back to the walker, which these programs never use anyway.

## Rebuilding the BPF objects

Needs clang ≥ 14, llvm-strip, make, elfutils-libelf-devel:
```
git clone --branch v2.5.1 https://github.com/cloudflare/ebpf_exporter.git
make -C ebpf_exporter libbpf.a          # clones libbpf v1.5.0 and installs its headers
make -C bpf EBPF_EXPORTER=$PWD/ebpf_exporter   # writes charts/ebpf-pod-metrics/files/programs/*.bpf.o
```
Objects are CO-RE (BTF), so one build runs on every RHCOS kernel. Bump the chart `version` and upgrade; the
ConfigMap gets a new content hash and the DaemonSet rolls. After editing dashboard panels or subsystem regexes in
`tools/gen_dashboard.py`, run `python3 tools/gen_dashboard.py` (writes the dashboard and the recording rule).

## Caveats

- **Static/mirror pods** (etcd, kube-apiserver on a standalone control plane): the cgroup carries the static
  pod's UID, which differs from the mirror pod's API UID, so they won't join to `kube_pod_info`. Hosted control
  planes (HyperShift) run as regular pods and are fine.
- **Block IO** covers block devices only (LVMS/TopoLVM, local disks, iSCSI/FC, PowerFlex SDC). NFS/CephFS
  don't pass the block layer. Request-based multipath can count a request at both dm and the path device.
- **Throttle histogram** observes per-CPU run queues, so one throttled period on a 32-CPU node can produce up to
  32 observations. Use it for stall *duration*; use cAdvisor `container_cpu_cfs_throttled_periods_total` for counts.
- **Kernel-function names** use the exporter's `kstack` decoder with a single frame. The obvious `ksym` decoder only
  resolves exact symbol start addresses and re-reads all of `/proc/kallsyms` under a global lock on every miss —
  with sampled IPs that hung `/metrics` in testing.
- **Cardinality** of `node_kernel_function_samples_total`: one series per (function, context) seen on the node —
  a few hundred on a quiet node, low thousands on a busy one. If that's too much fleet-wide, drop the metric with
  a ServiceMonitor `metricRelabelings` rule and keep `node_cpu_samples_total` (tens of series per node). The address
  map holds 32k distinct IPs; overflow is counted in `node_kernel_function_samples_dropped_total`.
- **Interrupt/softirq time** is charged to whatever was running on that CPU (a pod, a service or idle). On idle
  CPUs it appears as context `idle` (shown as "interrupts on idle CPUs").
- **eBPF overhead panel** needs `sysctl kernel.bpf_stats_enabled=1` (MachineConfig/Tuned). Off by default.
- **Pod-level alerts** need the `kube_pod_info` join, which user-workload rules can't do across namespaces
  unless `ebpf-exporter` is in `namespacesWithoutLabelEnforcement`. Shipped rules cover exporter health only:
  the exporter-only rules are `leaf-prometheus` scoped; `EbpfExporterNearMemoryLimit` needs cAdvisor and KSM
  data, so it's a separate PrometheusRule evaluated by Thanos Ruler.

## Tested

On Linux 6.18 with exporter v2.5.1: `pod-runqlat`, `pod-tcp`, `pod-bio-latency` pass the verifier and attach;
UID resolution verified end-to-end for Guaranteed, Burstable and BestEffort slice layouts (including a nested
`crio-*.scope/container` sub-cgroup), on both the cgroup v1 cpu hierarchy and the v2 tree, with `system.slice`
excluded. `node-cpu-profile` attached on every CPU and correctly split a test `kubelet.service` CPU hog, a
`crio.service` syscall storm (with SLUB/memcg functions visible) and RCU slab freeing in `ksoftirqd`; scrapes ~30 ms.
`pod-cfs-throttling` (fentry) and
`pod-oomkill` (kprobe) compile but couldn't load in the test sandbox (kprobes compiled out; the upstream
`cfs-throttling` example fails identically there) — confirm on a node with `--config.check`.

Chart, with Helm v3.16.4 built from the official source tag: `helm lint`; renders for Kubernetes 1.29 (OCP 4.16)
in 13 value combinations, each asserting its effect (capabilities follow programs, ConfigMap hash rolls the
DaemonSet, rules/relabelings toggle, mirror + digest, existing SCC, dashboards); `values.schema.json` rejects typos
and bad types; every object passes strict validation (unknown fields = what the API server would silently prune)
against the Kubernetes 1.29, Prometheus Operator v0.73.2, OpenShift 4.16 SCC and grafana-operator v5 schemas; the BPF
objects extracted from the rendered ConfigMap are byte-identical to the chart files and load and attach in the
kernel; `promtool test rules` fires `EbpfExporterDown` and `EbpfExporterNearMemoryLimit` with correctly rendered
annotations; the stored Helm release is ~520–540 KiB of the 1 MiB Secret limit.
