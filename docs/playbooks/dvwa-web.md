# Playbook - DVWA (web, by security level)

**Target:** `http://dvwa` (host: `http://127.0.0.1:8080`, login `admin`/`password`)
**Authorization:** bundled lab only. See docs/METHODOLOGY.md § Scope.

DVWA's value is the **security slider** (low → medium → high → impossible): run the
same attack at each level to see insecure vs hardened code side by side. Create/Reset
the DB on first use; grab your `PHPSESSID` + `security` cookies for the tools.

| Module | Attack | Tool / skill | WSTG |
|--------|--------|--------------|------|
| SQL Injection | dump users table; compare low vs impossible | `sqli-dvwa` (sqlmap) | WSTG-INPV-05 |
| Command Injection | `; id`, `&& cat /etc/passwd` | manual / commix | WSTG-INPV-12 |
| XSS (Reflected/Stored/DOM) | classic payloads per level | manual, ZAP | WSTG-INPV-01/02 |
| File Upload | upload a webshell, bypass filters | manual | WSTG-BUSL-09 |
| File Inclusion (LFI/RFI) | `?page=../../../../etc/passwd` | manual, ffuf | WSTG-INPV-11 |
| CSRF | forge a password-change request | manual | WSTG-SESS-05 |
| Brute Force | login brute force | ffuf / hydra | WSTG-ATHN-03 |

**The lesson:** every attack that works at *low* should fail at *impossible* -
inspect "View Source" to see why (parameterized queries, escaping, tokens).
