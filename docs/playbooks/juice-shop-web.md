# Playbook — OWASP Juice Shop (web)

**Target:** `http://juice-shop:3000` (host: `http://127.0.0.1:3000`)
**Authorization:** bundled lab only. See docs/METHODOLOGY.md § Scope.

A modern Angular SPA + Node/Express API with the full OWASP Top 10 and ~100 hidden
challenges. Work it top-down.

| # | Phase | Do | Tool / skill | WSTG |
|---|-------|----|--------------|------|
| 1 | Recon | Fingerprint + crawl SPA routes and the REST API under `/api`, `/rest` | `recon` (httpx, katana) | WSTG-INFO |
| 2 | Automated | Broad template scan, then a ZAP baseline | `nuclei-scan`, `dast-zap` | WSTG-CONF |
| 3 | Injection | SQLi in the login (`' OR 1=1--`), NoSQL in search/order | manual + sqlmap | WSTG-INPV-05/06 |
| 4 | XSS | DOM XSS in search (`<iframe src=javascript:...>`), stored XSS | manual | WSTG-INPV-01 |
| 5 | Broken auth / access | Forge/alter JWT, access other users' baskets (IDOR) | manual | WSTG-ATHZ |
| 6 | Secrets/exposure | ftp dir, `/.well-known`, exposed admin, leaked keys | nuclei, katana | WSTG-CONF |

**Report** each confirmed issue with: title, severity (CVSS), WSTG id, ATT&CK tag
(e.g. T1190), reproduction, and remediation. Template in docs/METHODOLOGY.md § Reporting.
