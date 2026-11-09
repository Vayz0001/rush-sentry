# rush-sentry — Gold-Standard Roadmap (v2)

> Consolidated from a 4-agent research sweep on 2026-11-09 (web-verified).
> Everything here is **additive**: the v0 toolkit (scan / lab / notify) is
> feature-complete and self-scans clean. This is how it becomes exceptional.
> Guiding constraints kept throughout: **Apache-2.0 cleanliness**, **BYOCli**
> (ship deterministic tools, no embedded LLM), **authorized/defensive use only**.

---

## A. `scan` — sharpen the static-analysis stack

### Tier 1 (do first — high signal, low cost, clean license)
- **`secrets`: add gitleaks git-history mode.** Today we run `gitleaks dir` (working
  tree only), which misses secrets buried in commit history — the whole point of
  git secret scanning. Use `gitleaks git` when the target is a repo; keep `dir`
  for non-git artifacts. Pair with `--baseline-path` so only *new* leaks fail CI.
  (MIT, no new dependency.)
- **NEW `ci` subcommand → zizmor.** Audits GitHub Actions for template injection,
  unpinned actions, over-broad `GITHUB_TOKEN`, secret exposure — a vuln class none
  of the current four scanners touch. MIT, Rust, very active, native SARIF.
- **`sast`: Semgrep → Opengrep.** IMPORTANT licensing finding: the Semgrep engine is
  fine (LGPL, run as a subprocess), but `p/default` **rules** are under the *Semgrep
  Rules License v1.0* — not OSS, "internal business use only, no redistribution, no
  SaaS." For an Apache-2.0 toolkit that silently pushes those onto every user,
  that's a cleanliness smell. **Opengrep** is a drop-in LGPL-2.1 fork (same rule
  format, same SARIF). Make registry rulesets an explicit, documented opt-in; ship
  a permissively-licensed default rule set.

### Tier 2 (strong adds — new capability / real extra signal, flag licenses)
- **NEW `sbom` subcommand → syft.** We have no SBOM capability today; SBOMs
  (CycloneDX/SPDX) are increasingly required (US EO 14028, EU CRA). Apache-2.0,
  very active. `grype` (also Apache-2.0) can scan the SBOM but **overlaps trivy fs**
  — add syft for SBOM, treat grype as optional.
- **`secrets`: trufflehog `--verify` (opt-in).** Its edge is *live credential
  validation* (actually calls the API to confirm a key works) → far fewer false
  positives on what matters. **AGPL-3.0** — fine as an invoked binary, but flag it
  and keep it off by default (network clause is friction for hosted use).
- **`iac`: hadolint for Dockerfiles (opt-in).** Dedicated Dockerfile linter (embedded
  ShellCheck) with depth trivy config lacks. **GPL-3.0** — flag, keep optional.

### Tier 3 (overlap / skip)
- osv-scanner — SKIP as a 2nd deps scanner (overlaps trivy; both use OSV.dev).
- checkov / KICS — optional IaC depth only; overlap trivy config.
- actionlint — nice workflow-hygiene companion, lower priority than zizmor.

### SARIF quality (raise the value of the merged report)
- **`security-severity` property on every rule** → GitHub bands findings
  (>=9.0 critical / 7.0-8.9 high / 4.0-6.9 medium / 0.1-3.9 low). Biggest enrichment
  lever during the jq-merge. Pass real CVSS through for CVE findings.
- **`partialFingerprints`** (e.g. primaryLocationLineHash) → reliable dedup +
  baselines across runs; makes "only new findings fail the build" work.
- **`suppressions` array** (`kind: inSource`) for allowlisted items (gitleaks
  allowlist, `nosemgrep`) — auditable, not silently dropped.
- Namespace `ruleId`s per tool (`gitleaks/…`, `opengrep/…`) so they don't collide;
  ensure every result has >=1 location; validate merged SARIF in CI.

---

## B. `lab` — add an attacker toolbox + a documented methodology

Today the lab ships only the *targets*. Add the *means* and the *method*:

- **NEW off-by-default `toolbox` container** (`profiles: ["attacker"]`), attached
  **only to the existing `internal: true` airgapped network** (reaches the targets,
  no egress to internet/host). Same hardening as the targets. Tools (minimal set):
  **OWASP ZAP** (Apache-2.0, headless Automation Framework) · **nuclei** (MIT, the
  modern Nikto successor) · **ffuf** (MIT) · **httpx + katana** (MIT, SPA-aware
  crawl) · **schemathesis** (MIT — shines against VAmPI's OpenAPI) · **sqlmap**
  (GPL — installed at build, not vendored). Optional: feroxbuster, commix.
  > Apache-2.0 stays clean: GPL tools are installed from upstream at image-build
  > and invoked as separate processes ("mere aggregation"), never vendored/linked.
- **5 skill packs** (`SKILL.md`): recon · dast-zap · nuclei-scan · api-vampi ·
  sqli-dvwa. Each **opens with a mandatory authorization gate**.
- **3 playbooks**: juice-shop (web) · dvwa (web, by security level) · vampi (API —
  the flagship: schemathesis + manual OWASP API Top 10 2023 walkthrough).
- **`METHODOLOGY.md`**: OWASP **WSTG v4.2** (web, test-ID-addressable) + OWASP **API
  Security Top 10 (2023)** (API) + **MITRE ATT&CK** tags; PTES as the phase spine.
- **Three independent guardrails**: no-egress container → agent-side authorization
  gate → CLI target allow-list (refuse any target not on the lab network).

---

## C. `notify` / pwn watch — expand the threat-intel feeds (stays stdlib-only)

Tiered rollout, highest signal first. Match on **package+ecosystem+version**, not
CVE-name scraping; dedup by CVE id; alert only on *new/escalated* findings.

- **Tier 1**
  1. **OSV.dev `querybatch`** (`POST api.osv.dev/v1/querybatch`) — the core matcher.
     No auth, version-aware, covers PyPI/npm/Go/crates/Maven/… Feed it trivy's SBOM.
  2. **EPSS** (`api.first.org/data/v1/epss`) — exploit-probability score; the noise
     filter. Enrich the CVEs you already have; **threshold EPSS >= 0.5** (or
     percentile >= 0.95) — cuts volume >90% while keeping what's actually exploited.
  3. **OpenSSF malicious-packages** — supply-chain *malware* (new threat class, not
     just CVEs). Already ingested into OSV, so Tier-1 #1 partly covers it; clone the
     repo for the full feed. A malicious dep = act-now critical.
- **Tier 2**: GitHub Advisory DB (git clone, OSV-format, no auth) · VulnCheck KEV
  (broader than CISA; free but needs a token) · NVD 2.0 (enrich only; 5 req/30s).
- **Tier 3** (exploit-available *flags*, enrichment only): Nuclei templates (by CVE)
  · Exploit-DB · Metasploit. Skip HIBP (paid, off-mission).
- **Tiered alerting**: CRITICAL/page = malware OR CISA/VulnCheck KEV OR PoC exists;
  HIGH = EPSS>=0.5 & CVSS>=7; DIGEST = the rest. Persist seen (CVE,pkg) pairs.

---

## D. Supply-chain / repo trust — be the exemplar

**Already done:** SHA-pinned actions, least-privilege `permissions:`, Scorecard
workflow, SECURITY.md + SLA, Dependabot (+cooldown), CODEOWNERS, dogfood SARIF.

**Prioritized next (highest trust-signal first):**
1. **Branch protection / ruleset on `main`** — required PR + 1 review + status checks
   (CI, dogfood), block force-push, CODEOWNERS review. (Scorecard Branch-Protection +
   Code-Review.) ~15 min.
2. **Signed releases via GitHub Artifact Attestations** (`actions/attest-build-
   provenance`, keyless Sigstore) → **SLSA Build L3**. Tag releases, attach a
   `SHA256SUMS`, attest it; verify with `gh attestation verify`. *Highest, least-
   common portfolio signal.*
3. **Dependency Review Action** as a required PR check.
4. **OpenSSF Best Practices (passing) badge** — self-certify at bestpractices.dev;
   we already meet most criteria. Put the badge in the README.
5. **Enable Private Vulnerability Reporting** (Settings → Security); link it in
   SECURITY.md.
6. **Dangerous-Workflow + webhook hardening** — both Scorecard *Critical* checks;
   cheap to pass.
7. **CI on `pull_request`** + add **CodeQL** (python) → Scorecard SAST signal.
8. **2FA / org hardening.**

**The 3-4 that scream "knows supply-chain security" for a job portfolio:** signed
releases + SLSA L3 (#2); a published Scorecard badge at 8+/10 (flip public); the
OpenSSF Best Practices badge (#4); branch-protection + dependency-review gating its
own PRs (#1, #3).

---

## Suggested sequencing
1. **Flip public** (unlocks free code scanning + Scorecard badge) → turn on branch
   protection + private vuln reporting (D1, D5). Zero code.
2. **scan Tier 1**: gitleaks history+baseline, zizmor `ci`, Opengrep swap (A).
3. **SARIF enrichment**: security-severity + partialFingerprints in the merge.
4. **notify Tier 1**: OSV querybatch + EPSS gating + malicious-packages (C).
5. **Signed releases / attestations** (D2) — the portfolio centerpiece.
6. **lab toolbox + methodology + playbooks** (B) — the biggest build; do last.
