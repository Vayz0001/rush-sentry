# rush-sentry - Testing Methodology

How to run an authorized web/API assessment with rush-sentry's lab + toolbox. The
framework is **OWASP WSTG** for web, **OWASP API Security Top 10 (2023)** for APIs,
with **MITRE ATT&CK** technique tags and a **PTES**-style phase spine.

## 1. Scope & Authorization (read first)
rush-sentry is **defensive / authorized use only**. Legitimate targets are:
- the **bundled lab** (`./bin/toolkit lab up`) - intentionally vulnerable, airgapped,
  and the sanctioned practice range; and
- systems you **own** or have **explicit written authorization** to test (signed
  engagement or in-scope bug-bounty program).

Testing anything else may be illegal (CFAA, Computer Misuse Act, equivalents). The
attacker toolbox is network-airgapped to the lab precisely so it cannot reach
outside it. Every skill pack opens with an authorization gate. **You are solely
responsible for your use.**

## 2. Framework mapping
| rush-sentry phase | PTES | WSTG section | API Top 10 (2023) | ATT&CK (example) |
|-------------------|------|--------------|-------------------|------------------|
| Recon & mapping | Intelligence gathering | WSTG-INFO | discovery | T1595 active scanning |
| Automated DAST | Vuln analysis | WSTG-CONF | - | T1190 exploit public app |
| Manual web testing | Exploitation | WSTG-INPV/ATHN/ATHZ/SESS | - | T1059, T1203 |
| API testing | Exploitation | - | API1-API10:2023 | T1078 valid accounts |
| Reporting | Reporting | - | - | - |

## 3. Phase 1 - Recon & Mapping  → skill: `recon`
Fingerprint (httpx), crawl incl. SPA routes (katana), discover hidden content
(ffuf). Output: the live endpoint/URL inventory that feeds every later phase.

## 4. Phase 2 - Automated DAST  → skills: `nuclei-scan`, `dast-zap`
Broad template detection (nuclei) then a deeper spider+active scan (ZAP). Treat
findings as leads; export SARIF/JSON to merge with `toolkit scan` output.

## 5. Phase 3 - Manual Web Testing  → playbooks: juice-shop, dvwa
The bugs scanners miss: injection, XSS, access control / IDOR, session flaws, file
upload/inclusion. Use DVWA's security levels to contrast vulnerable vs fixed code.

## 6. Phase 4 - API Testing  → skill: `api-vampi`, playbook: vampi
Schema-driven fuzzing (schemathesis) + a manual OWASP API Top 10 walkthrough (BOLA,
broken auth, mass assignment, excessive data exposure).

## 7. Phase 5 - Reporting
Record each confirmed finding as:
- **Title** · **Severity** (CVSS 3.1 vector + score) · **WSTG / API-Top-10 id** ·
  **ATT&CK technique** · **Affected URL/endpoint** · **Reproduction steps** ·
  **Evidence** · **Remediation**.
Keep it reproducible and factual. Re-test after remediation.

## Appendix - toolbox & licenses
Official/MIT-Apache: ZAP (Apache-2.0), nuclei/httpx/katana/ffuf (MIT),
schemathesis (MIT). GPL (invoked as separate containers, not vendored): sqlmap.
Community images (pinned): ffuf, sqlmap via `secsi/*`. See lab/README.md.
