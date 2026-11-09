# lab/ — isolated vulnerable-app range

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

- **OWASP Juice Shop** (`bkimminich/juice-shop`) — modern OWASP Top 10
- **DVWA** (`ghcr.io/digininja/dvwa`) — classic web vulns
- **VAmPI** (`erev0s/vampi`) — vulnerable REST API
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
