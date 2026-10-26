#!/usr/bin/env bash
# Builds an offline bundle for an air-gapped install, without oc mirror / oc-mirror. Run on a connected host.
#
#   tools/airgap-bundle.sh [OUT_DIR]          # default: dist/
#
# Uses skopeo, podman or docker (first found; force one with TOOL=...), logged in to ghcr.io (the CI image is
# private: a token with read:packages). The bundle holds the exporter image
# as a docker-archive, the packaged chart, a source snapshot (for an internal git / ArgoCD) and the loader:
#
#   ebpf-pod-metrics-airgap-<chart version>/
#     images/<image>-<tag>.tar           image (single platform, PLATFORM=linux/amd64 by default)
#     images.txt                         <source ref> <archive> <platform> <source digest>
#     charts/ebpf-pod-metrics-<v>.tgz    helm package
#     src/ebpf-pod-metrics-<v>.tar.gz    git archive of HEAD (skipped outside a git checkout)
#     airgap-load.sh                     run this on the disconnected side
#     SHA256SUMS
#
# Then carry ebpf-pod-metrics-airgap-<v>.tar across the gap and see airgap-load.sh.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
CHART="$ROOT/charts/ebpf-pod-metrics"
OUT=${1:-$ROOT/dist}
PLATFORM=${PLATFORM:-linux/amd64}

chart_field() { sed -n "s/^$1: *\"\{0,1\}\([^\" #]*\).*/\1/p" "$CHART/Chart.yaml"; }
values_field() { sed -n "/^image:/,/^[^ ]/s/^  $1: *\"\{0,1\}\([^\" #]*\).*/\1/p" "$CHART/values.yaml"; }

VERSION=$(chart_field version)
TAG=$(values_field tag); TAG=${TAG:-v$(chart_field appVersion)}
REPO=$(values_field repository)
[[ -n $(values_field registry) ]] && REPO=$(values_field registry)/${REPO#*/}
IMAGE=${IMAGE:-$REPO:$TAG}

pick_tool() {
  if [[ -n ${TOOL:-} ]]; then echo "$TOOL"; return; fi
  for t in skopeo podman docker; do
    if command -v "$t" >/dev/null; then echo "$t"; return; fi
  done
  echo "need one of skopeo, podman, docker" >&2; exit 1
}
TOOL=$(pick_tool)
command -v helm >/dev/null || { echo "need helm" >&2; exit 1; }
SHA256=(sha256sum); command -v sha256sum >/dev/null || SHA256=(shasum -a 256)

NAME=ebpf-pod-metrics-airgap-$VERSION
STAGE="$OUT/$NAME"
ARCHIVE=images/$(basename "$REPO")-$TAG.tar
rm -rf "$STAGE"
mkdir -p "$STAGE/images" "$STAGE/charts"

echo ">> $IMAGE ($PLATFORM) via $TOOL"
os=${PLATFORM%%/*}; arch=${PLATFORM#*/}
case $TOOL in
  skopeo)
    skopeo copy --override-os "$os" --override-arch "$arch" \
      "docker://$IMAGE" "docker-archive:$STAGE/$ARCHIVE:$IMAGE"
    digest=$(skopeo inspect --override-os "$os" --override-arch "$arch" --format '{{.Digest}}' "docker://$IMAGE")
    ;;
  podman|docker)
    "$TOOL" pull --platform "$PLATFORM" "$IMAGE"
    "$TOOL" save -o "$STAGE/$ARCHIVE" "$IMAGE"
    digest=$("$TOOL" image inspect --format '{{index .RepoDigests 0}}' "$IMAGE"); digest=${digest#*@}
    ;;
  *) echo "TOOL must be skopeo, podman or docker" >&2; exit 1 ;;
esac
echo "$IMAGE $ARCHIVE $PLATFORM $digest" > "$STAGE/images.txt"

echo ">> chart $VERSION"
helm lint "$CHART" >/dev/null
helm package "$CHART" -d "$STAGE/charts" >/dev/null

if git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1; then
  echo ">> source $(git -C "$ROOT" rev-parse --short HEAD)"
  mkdir -p "$STAGE/src"
  git -C "$ROOT" archive --format=tar.gz --prefix=ebpf-pod-metrics/ -o "$STAGE/src/ebpf-pod-metrics-$VERSION.tar.gz" HEAD
fi

cp "$ROOT/tools/airgap-load.sh" "$STAGE/"
(cd "$STAGE" && find . -type f ! -name SHA256SUMS | sort | xargs "${SHA256[@]}" > SHA256SUMS)
tar -C "$OUT" -cf "$OUT/$NAME.tar" "$NAME"
echo ">> $OUT/$NAME.tar ($(du -h "$OUT/$NAME.tar" | cut -f1))"
