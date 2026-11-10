#!/usr/bin/env bash
# secrets - gitleaks. Scans the working tree (dir mode) AND, when the target is a
# git repo, its full commit history (git mode) - because secrets are usually
# buried in old commits, which a working-tree-only scan misses entirely. Results
# from both passes are merged and deduped into one SARIF run on stdout. Honors an
# optional .gitleaks.toml (allowlists/baselines). History mode: set RS_GIT_HISTORY=0
# to disable. The no-findings case normalizes to a valid empty SARIF.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
source "$ROOT/bin/lib/common.sh"
rs_parse "$@"
rs_need_docker

IMG="${RS_IMG_GITLEAKS:-ghcr.io/gitleaks/gitleaks:latest}"

TMP_OUT="$(mktemp -d)"
trap 'rm -rf "$TMP_OUT"' EXIT

conf_args=()
[[ -f "$TARGET/.gitleaks.toml" ]] && conf_args=(-c /src/.gitleaks.toml)

run_gitleaks() {  # $1 = mode (dir|git), $2 = report filename. Returns the
  # gitleaks exit code; with --exit-code 0 a non-zero return is a real scanner
  # error (not "secrets found"), so the caller can fail closed instead of hide it.
  local rc=0
  docker run --rm --network none \
    -v "$TARGET:/src:ro" -v "$TMP_OUT:/out" \
    "$IMG" "$1" /src --no-banner "${conf_args[@]}" \
    --report-format sarif --report-path "/out/$2" --exit-code 0 \
    >/dev/null 2>&1 || rc=$?
  return "$rc"
}

# Always scan the working tree. Fail closed on a real scanner error.
run_gitleaks dir dir.sarif || rs_err error "gitleaks dir scan failed (exit $?)" 1
# Scan commit history when the target is a git repo (unless disabled).
if [[ -d "$TARGET/.git" && "${RS_GIT_HISTORY:-1}" != "0" ]]; then
  run_gitleaks git git.sarif || rs_err error "gitleaks git-history scan failed (exit $?)" 1
fi

shopt -s nullglob
files=("$TMP_OUT"/*.sarif)

if [[ ${#files[@]} -eq 0 ]]; then
  rs_err error "gitleaks ran but produced no SARIF report (unexpected)" 1
fi

# Merge every pass into one gitleaks run, deduping identical findings
# (same rule + file + line) that both the dir and git passes can surface.
jq -s '
  {
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "version": "2.1.0",
    "runs": [
      {
        "tool": ( [ .[].runs[0].tool ] | map(select(. != null)) | (.[0] // {"driver":{"name":"gitleaks"}}) ),
        "results": (
          [ .[].runs[].results[] ]
          | unique_by([
              .ruleId,
              (.locations[0].physicalLocation.artifactLocation.uri // ""),
              (.locations[0].physicalLocation.region.startLine // 0),
              (.partialFingerprints.commitSha // "")
            ])
        )
      }
    ]
  }
' "${files[@]}"
