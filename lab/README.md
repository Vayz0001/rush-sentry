# lab/ - isolated vulnerable-app range

> ## ⛔ DO NOT EXPOSE
> The apps here are **intentionally vulnerable**. They must only ever run on an
> **isolated Docker network with no outbound route**, with web UIs bound to
> `127.0.0.1` only. Never publish these ports to a public interface, and never
> run this lab on a machine that routes to networks you care about.

## What this is

A practice range of deliberately-vulnerable web apps you attack to learn and to
exercise the scanners. Built in **Phase 3**. Host is x86_64, so all targets run
natively (no emulation).

## Planned targets

- **OWASP Juice Shop** (`bkimminich/juice-shop`) - modern OWASP Top 10
- **DVWA** (`ghcr.io/digininja/dvwa`) - classic web vulns
- **VAmPI** (`erev0s/vampi`) - vulnerable REST API
- rotate in: **WebGoat**, **crAPI** (API Top 10)

## Isolation model (enforced in docker-compose.yml)

- single bridge network `internal: true` → **no route off the box**; a reverse
  shell or payload in a target can't phone home or pivot
- targets attach to the internal network **only**
- web UIs reached via loopback-bound ports: `127.0.0.1:PORT:...`
- hardening per container: no `--privileged`, `cap_drop: ALL`,
  `no-new-privileges: true`, `read_only`+`tmpfs` where possible, mem/cpu/pids limits
- **verify the airgap after every `up`**: from inside a target,
  `wget -T3 https://example.com` must FAIL (blocked = good)

## Attacker toolbox (profile: `attacker`, off by default)

The lab ships an optional set of pentest tools as `--profile attacker` services,
attached **only to the airgapped `labnet`** - they can reach the targets by service
name (`http://juice-shop:3000`, `http://dvwa`, `http://vampi:5000`) but have **no
route to the internet or host**, so the network itself scopes them to the lab.

```
./bin/toolkit lab up --attacker        # start targets + pre-pull the toolbox
./bin/toolkit lab attack httpx  -u http://juice-shop:3000 -title -tech-detect
./bin/toolkit lab attack nuclei -u http://vampi:5000 -severity critical,high
./bin/toolkit lab attack zap    zap-baseline.py -t http://juice-shop:3000
```

Tools (images): `nuclei` `httpx` `katana` (projectdiscovery, MIT) · `ffuf`
`sqlmap` (community `secsi/*`, pinned) · `schemathesis` (MIT) · `zap`
(`ghcr.io/zaproxy/zaproxy`, Apache-2.0). GPL tools (sqlmap) run as separate
containers and are never vendored, so the repo stays Apache-2.0.

Workflows live in `skills/*/SKILL.md` (each with an authorization gate) and
target playbooks in `docs/playbooks/`. Method: `docs/METHODOLOGY.md`.
**Authorized / defensive use only.**
