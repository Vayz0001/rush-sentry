---
name: api-vampi
description: Test the VAmPI vulnerable REST API — schemathesis conformance fuzzing plus a manual OWASP API Top 10 (2023) walkthrough (BOLA, broken auth, mass assignment).
---

# API testing — VAmPI

> ⚠️ **AUTHORIZATION GATE — read before running.** These tools are for the
> **bundled rush-sentry lab** (airgapped, intentionally vulnerable) or a target the
> user has **explicitly confirmed** they own or are authorized to test (signed
> engagement / in-scope bug bounty). If the target is not a lab service and the
> user has not confirmed authorization, **STOP and ask.** Unauthorized scanning may
> be illegal (CFAA / Computer Misuse Act). Defensive use only.

## When to use
Against the VAmPI target (or any OpenAPI-documented API you're authorized to
test). VAmPI ships an OpenAPI spec, so schemathesis can derive test cases
automatically; then you check the logic flaws scanners miss.

## Preconditions
```
./bin/toolkit lab up && ./bin/toolkit lab verify   # expect BLOCKED
```
VAmPI at `http://vampi:5000` (OpenAPI at `/openapi.json`).

## Steps
1. **Schema-driven fuzzing** (schemathesis) — status/schema conformance, 500s,
   auth gaps, derived from the spec:
   ```
   ./bin/toolkit lab attack schemathesis run http://vampi:5000/openapi.json --checks all
   ```
2. **Manual OWASP API Top 10 (2023)** — the logic bugs:
   - **API1 BOLA**: register two users, read user A's object as user B by swapping
     the id (e.g. `GET /users/v1/{username}`). Unauthorized object access = BOLA.
   - **API2 Broken Auth**: hit authenticated endpoints without/with a forged token;
     check user/password **enumeration** on login + register.
   - **API3 Mass assignment / excessive data**: look for a debug/admin field you
     can set on register (VAmPI lets you become admin), and endpoints leaking all
     users' data.
   - **API6 Unrestricted resource consumption**: unbounded list endpoints.

## Methodology
OWASP **API Security Top 10 (2023)** (note: 2023 dropped Injection as its own
category — focus on BOLA/auth/mass-assignment). docs/METHODOLOGY.md.
