---
name: recon
description: Map a lab web target's surface - live endpoints, tech stack, hidden content - with httpx, katana, and ffuf before deeper testing.
---

# Recon & content discovery

> ⚠️ **AUTHORIZATION GATE - read before running.** These tools are for the
> **bundled rush-sentry lab** (airgapped, intentionally vulnerable) or a target the
> user has **explicitly confirmed** they own or are authorized to test (signed
> engagement / in-scope bug bounty). If the target is not a lab service and the
> user has not confirmed authorization, **STOP and ask.** Unauthorized scanning may
> be illegal (CFAA / Computer Misuse Act). Defensive use only.

## When to use
First pass against a web target: confirm it's up, fingerprint the stack, crawl the
app (including SPA routes), and brute-force hidden paths. Feeds every later step.

## Preconditions
```
./bin/toolkit lab up            # start the targets
./bin/toolkit lab verify        # must print BLOCKED (airgap holds)
```
Targets on labnet: `http://juice-shop:3000` · `http://dvwa` · `http://vampi:5000`.

## Steps
1. **Probe + fingerprint** (httpx):
   ```
   ./bin/toolkit lab attack httpx -u http://juice-shop:3000 -title -tech-detect -status-code
   ```
2. **Crawl the app** - katana is JS-aware, so it finds SPA routes a classic
   dir-buster misses (ideal for Juice Shop's Angular front end):
   ```
   ./bin/toolkit lab attack katana -u http://juice-shop:3000 -jc -d 3
   ```
3. **Content discovery** (ffuf) - needs a wordlist mounted into the container;
   point FUZZ at the path you want to brute-force:
   ```
   ./bin/toolkit lab attack ffuf -u http://juice-shop:3000/FUZZ -w /wordlist.txt -mc 200,301,302
   ```

## Reading the output
httpx → what's alive + the stack; katana → the real URL/endpoint inventory to
feed nuclei/ZAP; ffuf → hidden admin panels, backups, API roots.

## Methodology
Maps to OWASP WSTG **Information Gathering** (WSTG-INFO). See docs/METHODOLOGY.md.
