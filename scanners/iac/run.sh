#!/usr/bin/env bash
# iac — trivy config scan (IaC / Dockerfile misconfig). SARIF to stdout.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
source "$ROOT/bin/lib/common.sh"
rs_parse "$@"
rs_need_docker

IMG="${RS_IMG_TRIVY:-aquasec/trivy:latest}"
RS_NET=bridge
CACHE="${RS_TRIVY_CACHE:-$ROOT/.trivycache}"
mkdir -p "$CACHE"

docker run --rm --network "$RS_NET" \
  -v "$TARGET:/src:ro" -v "$CACHE:/root/.cache/trivy" -w /src \
  "$IMG" config --quiet --format sarif /src
