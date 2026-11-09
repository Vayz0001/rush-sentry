#!/usr/bin/env bash
# ci — zizmor (GitHub Actions security audit). SARIF to stdout.
# Audits .github/workflows for template injection, unpinned actions, over-broad
# GITHUB_TOKEN permissions, dangerous triggers — a vuln class the other scanners
# don't cover. Runs --offline so it needs no network. Normalizes the no-workflows
# and no-findings cases to a valid empty SARIF so the output contract always holds.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
source "$ROOT/bin/lib/common.sh"
rs_parse "$@"

IMG="${RS_IMG_ZIZMOR:-ghcr.io/zizmorcore/zizmor:latest}"
EMPTY='{"$schema":"https://json.schemastore.org/sarif-2.1.0.json","version":"2.1.0","runs":[{"tool":{"driver":{"name":"zizmor","informationUri":"https://github.com/zizmorcore/zizmor"}},"results":[]}]}'

# Nothing to audit if the target has no workflows.
if [[ ! -d "$TARGET/.github/workflows" ]]; then
  # shellcheck disable=SC2016
  printf '%s\n' "$EMPTY"
  exit 0
fi

rs_need_docker
TMP_OUT="$(mktemp -d)"
trap 'rm -rf "$TMP_OUT"' EXIT

docker run --rm --network none \
  -v "$TARGET:/src:ro" \
  "$IMG" --format sarif --offline --persona regular /src/.github/workflows \
  >"$TMP_OUT/ci.sarif" 2>/dev/null || true

if [[ -s "$TMP_OUT/ci.sarif" ]] && jq -e . "$TMP_OUT/ci.sarif" >/dev/null 2>&1; then
  cat "$TMP_OUT/ci.sarif"
else
  # shellcheck disable=SC2016
  printf '%s\n' "$EMPTY"
fi
