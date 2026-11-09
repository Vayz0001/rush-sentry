#!/usr/bin/env bash
# sbom — syft (Software Bill of Materials). SPDX-JSON to stdout.
# NOTE: an SBOM is an inventory artifact, not SARIF findings, so this is a
# standalone capability — `scan all` does not merge it into combined.sarif.
# It answers "what is actually in this project?" (deps, versions, licenses),
# which is increasingly required (US EO 14028, EU CRA) and feeds vuln tooling.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
source "$ROOT/bin/lib/common.sh"
rs_parse "$@"
rs_need_docker

IMG="${RS_IMG_SYFT:-anchore/syft:latest}"
FORMAT="${RS_SBOM_FORMAT:-spdx-json}"

docker run --rm --network none \
  -v "$TARGET:/src:ro" \
  "$IMG" scan dir:/src -o "$FORMAT" -q
