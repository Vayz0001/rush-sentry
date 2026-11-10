---
name: dast-zap
description: Drive OWASP ZAP headlessly (spider + passive + active scan) against a lab target and read the report.
---

# OWASP ZAP - full DAST

> ⚠️ **AUTHORIZATION GATE - read before running.** These tools are for the
> **bundled rush-sentry lab** (airgapped, intentionally vulnerable) or a target the
> user has **explicitly confirmed** they own or are authorized to test (signed
> engagement / in-scope bug bounty). If the target is not a lab service and the
> user has not confirmed authorization, **STOP and ask.** Unauthorized scanning may
> be illegal (CFAA / Computer Misuse Act). Defensive use only.

## When to use
The deepest automated web scan: ZAP spiders the app, passively scans every
response, then actively probes for injection/XSS/etc. Heavier than nuclei; run it
when you want thorough coverage of one app.

## Preconditions
```
./bin/toolkit lab up && ./bin/toolkit lab verify   # expect BLOCKED
```
First run pulls the ZAP image (~1.5 GB) - be patient.

## Steps
```
# baseline (spider + passive) - safe, fast
./bin/toolkit lab attack zap zap-baseline.py -t http://juice-shop:3000

# full active scan - sends attack payloads (lab only!)
./bin/toolkit lab attack zap zap-full-scan.py -t http://juice-shop:3000
```
For repeatable scans, drive ZAP's **Automation Framework** with a `plan.yaml`
mounted into the container.

## Reading the output
ZAP prints WARN/FAIL per alert with the rule name and evidence URL. FAIL =
confirmed-ish, WARN = worth a manual look. Save the HTML/JSON report for the
write-up.

## Methodology
Covers much of WSTG **Input Validation** + **Session Management**. docs/METHODOLOGY.md.
