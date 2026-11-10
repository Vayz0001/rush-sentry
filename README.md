# rush-sentry

[![ci](https://github.com/Vayz0001/rush-sentry/actions/workflows/ci.yml/badge.svg)](https://github.com/Vayz0001/rush-sentry/actions/workflows/ci.yml)
[![codeql](https://github.com/Vayz0001/rush-sentry/actions/workflows/codeql.yml/badge.svg)](https://github.com/Vayz0001/rush-sentry/actions/workflows/codeql.yml)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/16508/badge)](https://www.bestpractices.dev/projects/16508)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/Vayz0001/rush-sentry/badge)](https://scorecard.dev/viewer/?uri=github.com/Vayz0001/rush-sentry)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

> **Defensive / authorized use only.** rush-sentry scans code you own and tests
> only deliberately-vulnerable practice targets you run yourself, assets you own,
> or systems you have **explicit written permission** to test. You are solely
> responsible for how you use it. See [SECURITY.md](SECURITY.md).

A **bring-your-own-CLI (BYOCli)** white-hat security toolkit. It ships the
deterministic tools, an isolated vulnerable-app lab, threat-intel notifications,
and agent **skill packs** - and leaves the "brain" to whatever AI agent CLI you
already use (Claude Code, Codex, omp, Gemini/Antigravity). No LLM keys baked in;
your agent + subscription drives it.

A [Rush Labs](https://rushlabs.ai) project.

## What's inside

| Dir | What |
|-----|------|
| `bin/` | the `toolkit` entrypoint (one CLI → subcommands, SARIF/JSON output) |
| `scanners/` | deterministic security scanners (secrets, deps/CVEs, SAST, IaC, supply-chain) |
| `lab/` | isolated Docker vulnerable-web-app range (airgapped, loopback-only) |
| `skills/` | agent instruction packs (`SKILL.md`) - the cross-agent "how to drive this" |
| `notify/` | threat-intel feeds (CISA KEV ∩ your deps) → Discord/Slack webhooks |
| `docs/` | methodology & playbooks (OWASP WSTG-based) |

## Quick start

```bash
git clone <this-repo> && cd rush-sentry
./setup.sh              # wires cross-agent shims (CLAUDE.md, GEMINI.md, skill dirs)
./bin/toolkit --help    # see available commands
```

Then open your agent CLI *inside this repo* - it reads `AGENTS.md` and the
`skills/` packs and can drive the scanners, lab, and notifications for you.

## Bring your own CLI

rush-sentry is driven by **your** agent. It's tested against Claude Code, Codex,
omp (Oh My Pi), and Gemini/Antigravity via the open `AGENTS.md` + Agent Skills
(`SKILL.md`) conventions. See [AGENTS.md](AGENTS.md).

## Status

Working across all five pillars (scan · lab · skills · notify · docs). See
[docs/methodology.md](docs/methodology.md) for the roadmap and how an agent drives
it end to end.

- **scan** - `toolkit scan all` runs secrets/deps/sast/iac → one merged SARIF
- **lab** - `toolkit lab up` → isolated, airgapped Juice Shop / DVWA / VAmPI
- **notify** - `toolkit notify run` → CISA KEV ∩ your deps → Discord/Slack
- **skills** - `run-scan`, `triage-findings` packs for your agent CLI

## License

[Apache-2.0](LICENSE). The lab under `lab/` is *intentionally vulnerable* - do
not expose it to any network. Scanners are scoped away from it to avoid false
positives.
