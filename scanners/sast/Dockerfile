# Opengrep image. Opengrep publishes no official container, so we build a small
# one from the upstream install script. Opengrep is an LGPL-2.1 fork of the
# Semgrep OSS engine — same rule format and SARIF output, but no account, no
# telemetry, and none of the Semgrep-registry ToS attached to the engine itself.
#
# NOTE (rules licensing): registry rulesets fetched via `--config p/...` remain
# third-party-licensed (Semgrep Rules License v1.0: internal use, no redistribute,
# no SaaS). rush-sentry does NOT vendor them; they are fetched at scan time and the
# ruleset is overridable via RS_OPENGREP_CONFIG. See docs/LEVELUP.md.
#
# Runs as a non-root user (uid 1000) so the toolkit's own IaC scan stays clean;
# output is written to a bind-mounted /out owned by the invoking user (also 1000).
FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates git \
 && rm -rf /var/lib/apt/lists/* \
 && curl -fsSL "https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh" -o /tmp/install.sh \
 && bash /tmp/install.sh \
 && mv /root/.opengrep /opt/opengrep \
 && ln -sf "$(find /opt/opengrep -type f -name opengrep | head -1)" /usr/local/bin/opengrep \
 && chmod -R a+rX /opt/opengrep \
 && rm -f /tmp/install.sh \
 && useradd --create-home --uid 1000 scanner

USER scanner
ENV HOME=/home/scanner

HEALTHCHECK CMD ["opengrep", "--version"]
ENTRYPOINT ["opengrep"]
