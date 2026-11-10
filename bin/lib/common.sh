#!/usr/bin/env bash
# common.sh - shared helpers for scanner wrappers. Sourced, not executed.
set -euo pipefail

# Emit a JSON error object on stderr (agent-parseable) and exit with a code.
rs_err() { # rs_err <code-string> <message> <exit-num>
  printf '{"error":%s,"code":%s}\n' \
    "$(jq -Rn --arg m "$2" '$m')" "$(jq -Rn --arg c "$1" '$c')" >&2
  exit "${3:-1}"
}

rs_need_docker() {
  command -v docker >/dev/null 2>&1 || rs_err error "docker is required but not found" 1
  docker info >/dev/null 2>&1 || rs_err error "docker daemon not reachable" 1
}

# Parse the common --target/--format flags. Sets TARGET (absolute) and FORMAT.
rs_parse() {
  TARGET="."; FORMAT="sarif"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --target) TARGET="${2:?--target needs a value}"; shift 2;;
      --format) FORMAT="${2:?--format needs a value}"; shift 2;;
      *) rs_err input "unknown flag: $1" 3;;
    esac
  done
  case "$FORMAT" in sarif|json) ;; *) rs_err input "unsupported --format: $FORMAT (sarif|json)" 3;; esac
  TARGET="$(cd "$TARGET" 2>/dev/null && pwd)" || rs_err input "target not found: $TARGET" 3
}

# Run a scanner image with the target mounted read-only at /src.
# Network defaults to "none" (safest when scanning untrusted code); scanners that
# need to fetch a vuln DB or rule set set RS_NET=bridge before calling.
# rs_docker <image> <args...>
rs_docker() {
  local img="$1"; shift
  docker run --rm --network "${RS_NET:-none}" \
    -v "$TARGET:/src:ro" -w /src \
    "$img" "$@"
}
