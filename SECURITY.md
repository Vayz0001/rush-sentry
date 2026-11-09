# Security Policy

## Authorized / defensive use only

rush-sentry is a defensive security toolkit. It is intended **only** for:

- scanning code and repositories **you own**;
- testing the **deliberately-vulnerable** practice targets bundled in `lab/`,
  which you run on your own isolated machine; and
- testing external systems you **own** or have **explicit written permission**
  (e.g. a signed engagement or an in-scope bug-bounty program) to test.

Using this tool to access, scan, probe, or attack systems you do not own and are
not authorized to test may be **illegal** (e.g. CFAA in the US, the Computer
Misuse Act in the UK, and equivalents elsewhere). **You are solely responsible
for your use of this software.** The authors accept no liability — see
[LICENSE](LICENSE).

## The lab is intentionally vulnerable

The applications under `lab/` contain **known, deliberate vulnerabilities** for
practice. **Do not expose the lab to any untrusted network.** It is configured to
run on an isolated Docker network with no outbound route and ports bound to
`127.0.0.1` only. Our own scanners are scoped to ignore `lab/` so its planted
vulnerabilities don't generate false findings against this repo.

## Reporting a vulnerability

If you find a security issue **in rush-sentry itself** (not in the intentionally
vulnerable lab), please report it privately via **GitHub Security Advisories**
("Report a vulnerability" on the repo's Security tab) rather than opening a public
issue.

- **Initial response:** we aim to acknowledge your report within **3 business
  days** (and always within 14 days).
- **Disclosure:** we coordinate a fix and public disclosure on a **~90-day**
  timeline, crediting the reporter unless you prefer otherwise.
- Please do not publicly disclose the issue until we've had a chance to address it.
