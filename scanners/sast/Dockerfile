# Opengrep image. Opengrep publishes no official container, so we build a small
# one around a pinned, checksum-verified release binary. Opengrep is an LGPL-2.1
# fork of the Semgrep OSS engine - same rule format and SARIF output, but no
# account, no telemetry, and none of the Semgrep-registry ToS attached to the
# engine itself.
#
# Supply chain: we pin a specific opengrep release and verify the downloaded
# binary's SHA-256 before use, instead of piping an unpinned upstream install
# script into a shell (trust-on-first-use). To upgrade, bump OPENGREP_VERSION
# and both hashes together.
#
# NOTE (rules licensing): registry rulesets fetched via `--config p/...` remain
# third-party-licensed (Semgrep Rules License v1.0: internal use, no redistribute,
# no SaaS). rush-sentry does NOT vendor them; they are fetched at scan time and the
# ruleset is overridable via RS_OPENGREP_CONFIG. See docs/LEVELUP.md.
#
# Runs as a non-root user (uid 1000) so the toolkit's own IaC scan stays clean;
# output is written to a bind-mounted /out owned by the invoking user (also 1000).
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

ARG OPENGREP_VERSION=v1.33.1
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends curl ca-certificates git; \
    rm -rf /var/lib/apt/lists/*; \
    case "$(uname -m)" in \
      x86_64)  asset=opengrep_manylinux_x86;     sha=46e8133cc490f9f50518061590ce2f6be5a08afaeda034471c0ceda4b3899808 ;; \
      aarch64) asset=opengrep_manylinux_aarch64; sha=d1433f63a90b8bc0b6ad4b498a13b372b856ce9a754a43484ba4920fe2d76dcf ;; \
      *) echo "unsupported build arch: $(uname -m)" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/opengrep/opengrep/releases/download/${OPENGREP_VERSION}/${asset}" -o /usr/local/bin/opengrep; \
    echo "${sha}  /usr/local/bin/opengrep" | sha256sum -c -; \
    chmod +x /usr/local/bin/opengrep; \
    useradd --create-home --uid 1000 scanner

USER scanner
ENV HOME=/home/scanner

HEALTHCHECK CMD ["opengrep", "--version"]
ENTRYPOINT ["opengrep"]
