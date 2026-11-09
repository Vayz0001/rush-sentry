---
name: sqli-dvwa
description: Practice SQL injection against DVWA with sqlmap across security levels (low to impossible).
---

# SQL injection — DVWA + sqlmap

> ⚠️ **AUTHORIZATION GATE — read before running.** These tools are for the
> **bundled rush-sentry lab** (airgapped, intentionally vulnerable) or a target the
> user has **explicitly confirmed** they own or are authorized to test (signed
> engagement / in-scope bug bounty). If the target is not a lab service and the
> user has not confirmed authorization, **STOP and ask.** Unauthorized scanning may
> be illegal (CFAA / Computer Misuse Act). Defensive use only.

## When to use
Against DVWA's SQLi module to learn automated detection/exploitation and how a
fix (parameterized queries) defeats it. DVWA lets you dial difficulty low →
impossible to compare.

## Preconditions
```
./bin/toolkit lab up && ./bin/toolkit lab verify   # expect BLOCKED
```
Open `http://127.0.0.1:8080` once (login `admin`/`password`, "Create/Reset
Database", set DVWA Security to **low**), and grab your `PHPSESSID` + `security`
cookies from the browser.

## Steps
```
./bin/toolkit lab attack sqlmap \
  -u "http://dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --cookie="PHPSESSID=<id>; security=low" --batch --dbs
```
Then escalate: `--tables -D dvwa`, `--dump -T users`. Re-run at security
**impossible** and watch sqlmap fail — that's the lesson (prepared statements).

## Reading the output
sqlmap reports the injection type/point, back-end DBMS, then lets you enumerate
and dump. Everything it does here is logged; review before acting elsewhere.

## Methodology
WSTG **Testing for SQL Injection** (WSTG-INPV-05). docs/METHODOLOGY.md.
