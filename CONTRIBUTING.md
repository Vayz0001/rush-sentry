# Contributing to rush-sentry

Thanks for your interest! rush-sentry is a **defensive** security toolkit — please
keep contributions aligned with authorized, lawful use.

## Ground rules

- **Defensive/authorized use only.** Don't add features whose primary purpose is
  attacking systems without authorization, mass exploitation, or evasion for
  malicious use. The `lab/` targets are intentionally vulnerable and must stay
  isolated (internal network, loopback only) — see `lab/README.md`.
- **BYOCli.** The tool must not embed an LLM/provider integration or require API
  keys. Intelligence is the user's own agent CLI; we ship deterministic tools +
  skill packs (`AGENTS.md`, `skills/*/SKILL.md`).
- **Output contract is frozen after 1.0.** Additive changes only — never rename
  or remove commands, flags, JSON fields, or change exit-code meanings. Findings
  are SARIF 2.1.0.

## Dev setup

```bash
./setup.sh                 # wire cross-agent shims
pipx install pre-commit && pre-commit install
make test                  # run unit tests (pytest)
./bin/toolkit scan all --target . --format sarif | jq .runs   # dogfood
```

## Submitting

1. Branch from `main`; keep PRs focused.
2. `pre-commit run --all-files` and `make test` must pass (shellcheck,
   gitleaks, yaml/json, and the pytest unit tests).
3. New scanner wrappers: add a `scanners/<tool>/run.sh` that emits SARIF, register
   it in `scanners/MANIFEST.json`, and keep it runnable via Docker with the target
   mounted read-only.
4. Describe what you changed and how you tested it.

## Reporting security issues

See [SECURITY.md](SECURITY.md) — private disclosure via GitHub Security Advisories.
