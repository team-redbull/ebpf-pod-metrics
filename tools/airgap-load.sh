#!/usr/bin/env bash
# Disconnected side of tools/airgap-bundle.sh: verifies the bundle, pushes the image into an internal registry
# and writes values-airgap.yaml pinning it by digest. No oc mirror / oc-mirror needed.
#
#   tar xf ebpf-pod-metrics-airgap-<v>.tar && cd ebpf-pod-metrics-airgap-<v>
#   ./airgap-load.sh registry.internal:5000 [oci://registry.internal:5000/charts]
#
# The second argument also pushes the chart there (helm push). Log in first (skopeo/podman/docker login, and
# helm registry login for the chart). Uses skopeo, podman or docker (first found; force one with TOOL=...).
# Self-signed registry: TLS_VERIFY=false (skopeo/podman/helm; docker needs insecure-registries in daemon.json).
set -euo pipefail

REGISTRY=${1:?usage: $0 <registry[:port][/prefix]> [oci://chart-repo]}
REGISTRY=${REGISTRY%/}
CHART_REPO=${2:-}
TLS_VERIFY=${TLS_VERIFY:-true}
cd "$(dirname "$0")"

echo ">> verifying checksums"
if command -v sha256sum >/dev/null; then sha256sum -c --quiet SHA256SUMS; else shasum -a 256 -c --quiet SHA256SUMS; fi

pick_tool() {
  if [[ -n ${TOOL:-} ]]; then echo "$TOOL"; return; fi
  for t in skopeo podman docker; do
    if command -v "$t" >/dev/null; then echo "$t"; return; fi
  done
  echo "need one of skopeo, podman, docker" >&2; exit 1
}
TOOL=$(pick_tool)

read -r src archive _ _ < images.txt
path=${src#*/}       # ghcr.io/cloudflare/ebpf_exporter:v2.5.1 -> cloudflare/ebpf_exporter:v2.5.1
dest=$REGISTRY/$path
repo=${dest%:*}

echo ">> $archive -> $dest via $TOOL"
case $TOOL in
  skopeo)
    skopeo copy --dest-tls-verify="$TLS_VERIFY" "docker-archive:$archive" "docker://$dest"
    digest=$(skopeo inspect --tls-verify="$TLS_VERIFY" --format '{{.Digest}}' "docker://$dest")
    ;;
  podman)
    podman load -i "$archive"
    podman tag "$src" "$dest"
    podman push --tls-verify="$TLS_VERIFY" --digestfile .digest "$dest"
    digest=$(cat .digest); rm -f .digest
    ;;
  docker)
    docker load -i "$archive"
    docker tag "$src" "$dest"
    docker push "$dest"
    digest=$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$dest" | grep "^$repo@" | head -1)
    digest=${digest#*@}
    ;;
  *) echo "TOOL must be skopeo, podman or docker" >&2; exit 1 ;;
esac
[[ $digest == sha256:* ]] || { echo "could not read the pushed digest" >&2; exit 1; }

chart=$(ls charts/ebpf-pod-metrics-*.tgz)
if [[ -n $CHART_REPO ]]; then
  echo ">> $chart -> $CHART_REPO"
  insecure=; [[ $TLS_VERIFY == false ]] && insecure=--insecure-skip-tls-verify
  helm push "$chart" "$CHART_REPO" $insecure
fi

registry=${repo%%/*}
cat > values-airgap.yaml <<EOF
image:
  registry: $registry
  repository: ${repo#*/}
  digest: $digest
EOF

echo ">> wrote values-airgap.yaml ($repo@$digest)"
echo
echo "Install (namespace must exist with privileged PSA labels, see the guide):"
echo "  helm install ebpf-exporter $chart -n ebpf-exporter -f values-airgap.yaml"
