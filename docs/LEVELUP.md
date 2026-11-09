# rush-sentry — "Gold Standard" level-up roadmap

Synthesized from research (OpenSSF Scorecard + Best Practices, Trivy/Semgrep/
gitleaks docs, GitHub SARIF spec) + what our own dogfood scan found. Ordered
quick-wins-first. Defensive/authorized use throughout.

> Our dogfood self-scan already flagged the #1 quick win below (7× unpinned
> GitHub Actions) — the tool caught its own gap.

## A. Scanner rule quality

- **semgrep:** move `p/default` → `--config p/security-audit --config
  p/owasp-top-ten --config p/secrets` (security-maximal). Add `.semgrepignore`
  (vendor/test/generated); justify suppressions with `# nosemgrep: <rule>`.
  Pin/vendor rules for deterministic, offline self-scans.
- **gitleaks:** add a **git-history** mode (`gitleaks git`, needs `fetch-depth: 0`
  in CI) alongside the working-tree `dir` mode; ship `.gitleaks.toml`
  (`[extend] useDefault=true` + narrow allowlists for caches/test fixtures);
  support `--baseline-path` so only *new* secrets fail.
- **trivy:** make scanners explicit (`--scanners vuln,misconfig,secret,license`),
  add `--ignore-unfixed`, gate CI on `HIGH,CRITICAL`, ship `.trivyignore` with
  justification + expiry (`exp:`) comments.

## B. New scanner modules (ranked value-to-effort)

**Tier A (add first — high value, SARIF-native, fit our Docker wrappers):**
1. **zizmor** — GitHub Actions security scanner (template injection, excessive
   perms, dangerous triggers, unpinned actions…). Highest leverage since we're a
   CI-heavy repo; it hardens our *own* workflows. `scan actions`.
2. **actionlint** — Actions syntax/shell correctness (complements zizmor).
3. **osv-scanner** — second-opinion dep CVEs (different DB coverage than trivy).
4. **hadolint** — Dockerfile linter (we ship Dockerfiles/compose).

**Tier B (strong, moderate effort):**
5. **trufflehog `--results=verified`** — *live-credential verification* (near-zero
   FP "this secret is ACTIVE"); complements gitleaks (breadth) with proof.
6. **syft + grype** — SBOM artifact (feeds Scorecard SBOM + signed provenance).
7. checkov/KICS — only if we want deep IaC.

Lean gold-standard set: gitleaks(history) + trufflehog-verified + trivy(4
scanners) + osv-scanner + semgrep-security + **zizmor** + actionlint + hadolint.

## C. Findings pipeline

- **Severity normalization:** set SARIF `security-severity` (CVSS 0–10) on every
  rule so cross-tool severity is comparable (>9 crit, 7–8.9 high, 4–6.9 med,
  0.1–3.9 low).
- **Dedup / stable alerts:** populate `partialFingerprints`; keep ruleId+path
  stable across runs; dedup merged findings on (ruleId, file, line-hash).
- **Baselines** per tool so repeat runs stay green except genuinely new findings
  (the biggest "feels mature" signal).

## D. New `notify` feeds (the "pwn watch" ask — all free/defensive, → your webhook)

**Tier 1 (free, high-signal):**
- **`notify exploits`** — CVE *in your deps* gains a public PoC (PoC-in-GitHub,
  trickest/cve). "Something you run now has a working exploit."
- **`notify malware`** — OpenSSF **malicious-packages** ∩ your deps → typosquats /
  dependency-confusion / hijacked packages. Free, no key.
- **`notify epss`** — layer EPSS exploit-prediction score to rank alerts (FIRST
  API, free).
- **`notify kev`** (have it) — extend with **VulnCheck KEV** (free signup; earlier
  + wider than CISA).

**Tier 2 (needs a key):**
- **`notify breaches`** — HaveIBeenPwned for *your own domains* (⚠️ domain
  monitoring = paid key; Pwned-Passwords check is free).
- **`notify nuclei`** — new detection templates hitting your stack (free).

Reference bots to mirror: peass-ng/BotPEASS, mauvehed/kevvy.
**Cautions:** some sources need free keys (VulnCheck, abuse.ch, OTX); HIBP domain
= paid; ransomware.live ToS bars public rebroadcast (private alerts ok); never
auto-fetch/execute exploit code — alert only.

## E. Repo-quality (OpenSSF Scorecard + Best Practices badge)

**Quick wins (hours):**
- **Token-Permissions:** `permissions: contents: read` top-level in every
  workflow; write only per-job as needed.
- **Pinned-Dependencies:** hash-pin all Actions to commit SHAs (+ version
  comment); pin Docker base images by digest. *(dogfood flagged this)*
- **SECURITY.md:** add a contact + ≤14-day response + disclosure timeline.
- **Dependabot:** add `.github/dependabot.yml`.
- **Dangerous-Workflow:** no `pull_request_target`+PR-checkout; no untrusted
  `${{ }}` in inline `run:` (zizmor enforces).

**Short-term (days):**
- Branch protection Tiers 1–3 (block force-push/delete, require PR + review +
  status checks).
- **CHANGELOG.md** + Conventional Commits; self-certify **OpenSSF Best Practices
  passing badge** (mostly docs/process — satisfies Scorecard's CII check too).

**Medium-term (weeks):**
- Release automation (**release-please**) + **signed releases w/ SLSA provenance**
  via GitHub **Artifact Attestations** (`actions/attest-build-provenance`) →
  Signed-Releases 10/10 for a fraction of SLSA-generator effort.
- Publish **SBOM** (syft) per release.

**Flagged overkill (skip for a solo/portfolio repo):** OSS-Fuzz; full SLSA L3 via
slsa-github-generator+TUF (Artifact Attestations covers it); running every Tier
B+C scanner at once; large custom rule libraries; chasing the Code-Review check
(structurally hard solo — Scorecard gives implicit credit when merger≠committer).

## Prioritized master checklist

1. Token-Permissions on all workflows · 2. SHA-pin all Actions · 3. SECURITY.md
contact+timeline · 4. Dependabot · 5. gitleaks history mode + `.gitleaks.toml` ·
6. trivy explicit scanners + `.trivyignore` + ignore-unfixed · 7. **add zizmor +
actionlint** → then: semgrep security rulesets · osv-scanner + hadolint +
trufflehog-verified · SARIF security-severity + baselines · CHANGELOG +
branch protection · OpenSSF badge → then: release-please + signed releases +
SBOM. Interleave the Tier-1 `notify` feeds.
