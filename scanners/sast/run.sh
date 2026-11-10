#!/usr/bin/env bash
# sast - opengrep (LGPL-2.1 fork of the Semgrep OSS engine). SARIF to stdout.
# Opengrep removes the Semgrep account/telemetry/registry-ToS that attach to the
# upstream engine, keeping rush-sentry cleanly Apache-2.0. Rulesets fetched via
# --config are third-party licensed and overridable with RS_OPENGREP_CONFIG.
# The image is built locally from scanners/sast/Dockerfile (no official upstream
# image); `bin/toolkit` builds it on first use. Needs network to fetch rulesets.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
source "$ROOT/bin/lib/common.sh"
rs_parse "$@"
rs_need_docker

IMG="${RS_IMG_OPENGREP:-rush-sentry/opengrep:local}"
CONFIG="${RS_OPENGREP_CONFIG:-p/default}"

# Build the pinned image on first use (idempotent; fast once cached).
if ! docker image inspect "$IMG" >/dev/null 2>&1; then
  docker build -q -t "$IMG" "$ROOT/scanners/sast" >/dev/null
fi

TMP_OUT="$(mktemp -d)"
trap 'rm -rf "$TMP_OUT"' EXIT

rc=0
docker run --rm --network "${RS_NET:-bridge}" \
  -v "$TARGET:/src:ro" -v "$TMP_OUT:/out" \
  "$IMG" scan --config "$CONFIG" --sarif-output=/out/sast.sarif --quiet /src \
  >/dev/null 2>&1 || rc=$?

# A valid SARIF file means opengrep ran (exit 1 just signals findings). No
# valid file means a real error, so fail closed instead of emitting "all clear".
if [[ -s "$TMP_OUT/sast.sarif" ]] && jq -e . "$TMP_OUT/sast.sarif" >/dev/null 2>&1; then
  cat "$TMP_OUT/sast.sarif"
else
  rs_err error "opengrep produced no valid SARIF (exit $rc)" 1
fi
