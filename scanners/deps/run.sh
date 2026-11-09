#!/usr/bin/env bash
# deps — trivy filesystem scan (vulnerable dependencies / CVEs). SARIF to stdout.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
source "$ROOT/bin/lib/common.sh"
rs_parse "$@"
rs_need_docker

IMG="${RS_IMG_TRIVY:-aquasec/trivy:latest}"
RS_NET=bridge   # trivy fetches its vuln DB
CACHE="${RS_TRIVY_CACHE:-$ROOT/.trivycache}"
mkdir -p "$CACHE"

docker run --rm --network "$RS_NET" \
  -v "$TARGET:/src:ro" -v "$CACHE:/root/.cache/trivy" -w /src \
  "$IMG" fs --quiet --scanners vuln --format sarif /src
