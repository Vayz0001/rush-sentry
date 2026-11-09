#!/usr/bin/env bash
# sast — semgrep static analysis (code vulns). SARIF to stdout.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
source "$ROOT/bin/lib/common.sh"
rs_parse "$@"
rs_need_docker

IMG="${RS_IMG_SEMGREP:-semgrep/semgrep:latest}"
# Use a pinned registry ruleset (not "auto"): "auto" requires telemetry to be
# ON; a named ruleset lets us keep --metrics=off (privacy). Override via env.
RULES="${RS_SEMGREP_CONFIG:-p/default}"
RS_NET=bridge   # fetching the rule set needs network

# No --error: findings must not make the wrapper exit non-zero (handled downstream).
rs_docker "$IMG" semgrep scan \
  --config "$RULES" --sarif --quiet --metrics=off /src
