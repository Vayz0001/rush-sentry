#!/usr/bin/env bash
# setup.sh - wire cross-agent compatibility shims so one source of truth
# (AGENTS.md + skills/) serves Claude Code, Codex, omp, and Gemini/Antigravity.
# Safe to re-run (idempotent). Creates symlinks only; nothing here is committed.
set -euo pipefail
cd "$(dirname "$0")"

link() { # link <target> <linkname>
  local target="$1" name="$2"
  if [[ -L "$name" ]]; then rm -f "$name"; fi
  if [[ -e "$name" && ! -L "$name" ]]; then
    echo "  skip $name (exists, not a symlink)"; return
  fi
  ln -s "$target" "$name"; echo "  linked $name -> $target"
}

echo "rush-sentry setup: wiring cross-agent shims"

# Skills: canonical dir is skills/. Expose it where each CLI looks.
mkdir -p .claude .agents .omp
link "../skills" ".claude/skills"      # Claude Code
link "../skills" ".agents/skills"      # Codex
link "../skills" ".omp/skills"         # omp (Oh My Pi)

# Ambient context: omp also reads .omp/AGENTS.md
link "../AGENTS.md" ".omp/AGENTS.md"

# chmod the CLI + scripts
chmod +x bin/toolkit 2>/dev/null || true
find scanners notify -name '*.sh' -exec chmod +x {} + 2>/dev/null || true

echo "done. 'toolkit --help' to start; open your agent CLI in this dir to drive it."
