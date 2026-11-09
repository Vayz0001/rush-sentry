# Changelog

All notable changes to rush-sentry are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-11-09

First tagged release. rush-sentry is a defensive, bring-your-own-CLI security
toolkit. It ships deterministic Dockerized scanners, an isolated vulnerable-app
lab, and supply-chain threat-intel notifications, with no embedded LLM.

### Added

- Scanners (`toolkit scan`): secrets (gitleaks, working tree plus full git
  history), dependencies and CVEs (trivy), SAST (Opengrep, an LGPL fork of the
  Semgrep OSS engine), IaC and Dockerfile misconfiguration (trivy config), and a
  GitHub Actions security audit (zizmor). Findings are emitted as SARIF 2.1.0,
  and `scan all` merges them into one report.
- SBOM generation (`toolkit scan sbom`): an SPDX JSON inventory via syft.
- SARIF enrichment: per-rule `security-severity` (GitHub severity bands with
  real CVSS passthrough) and `partialFingerprints` for stable deduplication and
  baselines.
- Isolated lab (`toolkit lab`): airgapped OWASP Juice Shop, DVWA, and VAmPI
  behind a straddle-gateway, published on loopback only with no outbound route.
- Attacker toolbox (`toolkit lab attack`): nuclei, httpx, katana, ffuf, sqlmap,
  schemathesis, and OWASP ZAP, confined to the lab network for authorized
  practice only.
- Threat-intel watcher (`toolkit notify`): an SBOM inventory matched against OSV
  (version-aware, including malicious-package advisories), CISA KEV, and EPSS,
  with tiered alerts and state deduplication to a webhook.
- Agent skill packs (`AGENTS.md`, `skills/*/SKILL.md`) and WSTG, OWASP API
  Top 10, and MITRE ATT&CK playbooks under `docs/`.
- Supply-chain hardening: SHA-pinned GitHub Actions, least-privilege workflow
  permissions, CodeQL, dependency review, an OpenSSF Scorecard workflow, a
  signed-release workflow using GitHub Artifact Attestations (keyless Sigstore,
  SLSA Build L3), and CI that scans the repo against itself (dogfood).

[Unreleased]: https://github.com/Vayz0001/rush-sentry/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Vayz0001/rush-sentry/releases/tag/v0.1.0
