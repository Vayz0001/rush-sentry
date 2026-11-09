#!/usr/bin/env bash
# secrets — gitleaks (leaked keys/tokens, incl. git history). SARIF to stdout.
# gitleaks writes its report to a path; we mount a temp file for it (writing to
# /dev/stdout is unreliable under command substitution) and normalize the
# no-findings case to a valid empty SARIF so the output contract always holds.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
source "$ROOT/bin/lib/common.sh"
rs_parse "$@"
rs_need_docker

IMG="${RS_IMG_GITLEAKS:-ghcr.io/gitleaks/gitleaks:latest}"

TMP_OUT="$(mktemp -d)"
trap 'rm -rf "$TMP_OUT"' EXIT

docker run --rm --network none \
  -v "$TARGET:/src:ro" -v "$TMP_OUT:/out" \
  "$IMG" dir /src --no-banner \
  --report-format sarif --report-path /out/gitleaks.sarif --exit-code 0 \
  >/dev/null 2>&1 || true

if [[ -s "$TMP_OUT/gitleaks.sarif" ]] && jq -e . "$TMP_OUT/gitleaks.sarif" >/dev/null 2>&1; then
  cat "$TMP_OUT/gitleaks.sarif"
else
  # shellcheck disable=SC2016  # literal $schema in JSON, intentional
  printf '{"$schema":"https://json.schemastore.org/sarif-2.1.0.json","version":"2.1.0","runs":[{"tool":{"driver":{"name":"gitleaks","informationUri":"https://github.com/gitleaks/gitleaks"}},"results":[]}]}\n'
fi
