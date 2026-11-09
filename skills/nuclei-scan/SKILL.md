---
name: nuclei-scan
description: Run template-based vulnerability/misconfiguration detection against a lab target with nuclei, then triage the findings.
---

# nuclei — template DAST

> ⚠️ **AUTHORIZATION GATE — read before running.** These tools are for the
> **bundled rush-sentry lab** (airgapped, intentionally vulnerable) or a target the
> user has **explicitly confirmed** they own or are authorized to test (signed
> engagement / in-scope bug bounty). If the target is not a lab service and the
> user has not confirmed authorization, **STOP and ask.** Unauthorized scanning may
> be illegal (CFAA / Computer Misuse Act). Defensive use only.

## When to use
Fast, broad detection of known CVEs, misconfigurations, exposures and default
creds via community templates. Run after recon has given you live URLs.

## Preconditions
```
./bin/toolkit lab up && ./bin/toolkit lab verify   # expect BLOCKED
```
Note: the toolbox is airgapped, so nuclei uses the templates **bundled in the
image** (it can't fetch updates). That's fine for lab practice.

## Steps
```
# scan a single target with the default template set
./bin/toolkit lab attack nuclei -u http://juice-shop:3000

# scope to a severity / tag to cut noise
./bin/toolkit lab attack nuclei -u http://vampi:5000 -severity critical,high
./bin/toolkit lab attack nuclei -u http://dvwa -tags exposure,default-login
```

## Reading the output
Each line = `[template-id] [protocol] [severity] matched-URL`. Treat it as a
lead, not proof — confirm manually before reporting. Export SARIF/JSON with
`-sarif-export out.sarif` / `-json-export out.json` to merge with scan findings.

## Methodology
WSTG **Configuration & Deployment Management** + CVE validation. docs/METHODOLOGY.md.
