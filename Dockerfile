# Upstream ebpf_exporter with this repo's BPF programs baked in, so the image runs on its own
# (--config.dir=/etc/ebpf-pod-metrics --config.names=...). The chart still mounts the same files from its
# content-addressed ConfigMap over this path, so chart-driven program changes don't need a rebuild.
# Bump the base: new tag + its index digest (skopeo inspect --raw docker://... | sha256sum).
FROM ghcr.io/cloudflare/ebpf_exporter:v2.5.1@sha256:858e6f50ec33808aebf3e032535fcf0253ecf5e4269c6c38201c1b2b1762aae2

COPY charts/ebpf-pod-metrics/files/programs/ /etc/ebpf-pod-metrics/

LABEL org.opencontainers.image.source="https://github.com/team-redbull/ebpf-pod-metrics" \
      org.opencontainers.image.description="cloudflare/ebpf_exporter v2.5.1 + ebpf-pod-metrics BPF programs"
