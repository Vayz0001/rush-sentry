#!/usr/bin/env python3
"""rush-sentry threat-intel watcher ("pwn watch").

Builds a full dependency inventory (syft SBOM), then cross-references it against
several free threat-intel feeds and alerts in TIERS so a webhook ping is reserved
for things that can actually hurt you now:

  CRITICAL  malicious package (OpenSSF, via OSV MAL- advisories) OR a CVE on the
            CISA KEV catalog (actively exploited in the wild)
  HIGH      EPSS exploit-probability >= threshold (default 0.5)
  DIGEST    everything else - counted, not pinged

Feeds (all free, no key, stdlib urllib):
  - syft        full package inventory (ecosystem/name/version from purls)
  - OSV.dev     version-aware vuln matching (/v1/querybatch), incl. MAL- malware
  - CISA KEV    known-exploited catalog
  - EPSS        FIRST.org exploit-probability scores

State is persisted so a scheduled run only alerts on NEW or ESCALATED findings.
Pure stdlib. Defensive/authorized use only. Webhook is post-only; read from
$RUSH_SENTRY_WEBHOOK or ./.env.
"""
import argparse
import json
import os
import subprocess
import sys
import urllib.request
import urllib.error
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / "notify" / "state"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
EPSS_URL = "https://api.first.org/data/v1/epss"
SYFT_IMG = os.environ.get("RS_IMG_SYFT", "anchore/syft:latest")
UA = "rush-sentry/0.2 (+https://github.com/Vayz0001/rush-sentry)"
EPSS_THRESHOLD = float(os.environ.get("RS_EPSS_THRESHOLD", "0.5"))

TIERS = {"CRITICAL": 3, "HIGH": 2, "DIGEST": 1}


def load_env():
    env = ROOT / ".env"
    if env.exists():
        for line in env.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())


def _get_json(url, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def _post_json(url, body, timeout=30):
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


# ---------------------------------------------------------------- inventory ---
# map a syft/SPDX purl ecosystem to the OSV ecosystem name
PURL_TO_OSV = {
    "pypi": "PyPI", "npm": "npm", "golang": "Go", "cargo": "crates.io",
    "maven": "Maven", "gem": "RubyGems", "nuget": "NuGet", "composer": "Packagist",
    "hex": "Hex", "pub": "Pub", "conan": "ConanCenter", "apk": "Alpine",
    "deb": "Debian",
}


def parse_purl(purl):
    """pkg:pypi/jinja2@2.4.1 -> ('PyPI','jinja2','2.4.1'); None if unusable."""
    if not purl or not purl.startswith("pkg:"):
        return None
    body = purl[4:].split("?", 1)[0]
    if "/" not in body or "@" not in body:
        return None
    typ, rest = body.split("/", 1)
    name, version = rest.rsplit("@", 1)
    eco = PURL_TO_OSV.get(typ.lower())
    if not eco:
        return None
    if "/" in name:  # namespaced npm/golang: keep full path as the name
        name = name
    return (eco, name, version)


def inventory(target):
    """Run syft, return a deduped list of (ecosystem, name, version)."""
    try:
        out = subprocess.run(
            ["docker", "run", "--rm", "--network", "bridge",
             "-v", f"{target}:/src:ro", SYFT_IMG, "scan", "dir:/src",
             "-o", "spdx-json", "-q"],
            capture_output=True, text=True, timeout=300)
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        sys.stderr.write(f"[notify] syft inventory failed: {e}\n")
        return []
    try:
        spdx = json.loads(out.stdout or "{}")
    except json.JSONDecodeError:
        return []
    pkgs = {}
    for p in spdx.get("packages", []) or []:
        purl = None
        for ref in p.get("externalRefs", []) or []:
            if ref.get("referenceType") == "purl":
                purl = ref.get("referenceLocator")
                break
        parsed = parse_purl(purl)
        if parsed:
            pkgs[parsed] = True
    return sorted(pkgs)


# -------------------------------------------------------------------- feeds ---
def fetch_kev():
    STATE.mkdir(parents=True, exist_ok=True)
    cache = STATE / "kev.json"
    try:
        data = _get_json(KEV_URL, timeout=20)
        cache.write_text(json.dumps(data))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
        if cache.exists():
            sys.stderr.write(f"[notify] KEV fetch failed ({e}); using cache\n")
            data = json.loads(cache.read_text())
        else:
            sys.stderr.write(f"[notify] KEV fetch failed, no cache: {e}\n")
            return set()
    return {v["cveID"] for v in data.get("vulnerabilities", [])}


def osv_match(pkgs):
    """OSV querybatch -> {(eco,name,ver): [vuln_id,...]}. Order-matched response."""
    if not pkgs:
        return {}
    queries = [{"package": {"ecosystem": e, "name": n}, "version": v}
               for (e, n, v) in pkgs]
    try:
        resp = _post_json(OSV_BATCH, {"queries": queries})
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
        sys.stderr.write(f"[notify] OSV querybatch failed: {e}\n")
        return {}
    out = {}
    for pkg, result in zip(pkgs, resp.get("results", []) or []):
        ids = [v["id"] for v in (result.get("vulns") or []) if v.get("id")]
        if ids:
            out[pkg] = ids
    return out


def osv_hydrate(vuln_id):
    """Fetch one OSV record -> {cve, malicious, summary}."""
    try:
        rec = _get_json(OSV_VULN + vuln_id, timeout=20)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return {"cve": None, "malicious": vuln_id.startswith("MAL-"), "summary": ""}
    cve = None
    if vuln_id.startswith("CVE-"):
        cve = vuln_id
    for a in rec.get("aliases", []) or []:
        if a.startswith("CVE-"):
            cve = a
            break
    return {"cve": cve,
            "malicious": vuln_id.startswith("MAL-"),
            "summary": (rec.get("summary") or "").strip()}


def fetch_epss(cve_ids):
    """{cve: epss_float} for the given CVE ids (batched)."""
    scores = {}
    ids = [c for c in cve_ids if c]
    for i in range(0, len(ids), 90):
        chunk = ids[i:i + 90]
        try:
            data = _get_json(f"{EPSS_URL}?cve={','.join(chunk)}", timeout=20)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
            sys.stderr.write(f"[notify] EPSS fetch failed: {e}\n")
            continue
        for row in data.get("data", []) or []:
            try:
                scores[row["cve"]] = float(row.get("epss", 0) or 0)
            except (TypeError, ValueError):
                pass
    return scores


# ----------------------------------------------------------------- classify ---
def classify(finding, kev, epss):
    """Return a tier string for one finding dict."""
    if finding["malicious"]:
        return "CRITICAL"
    cve = finding.get("cve")
    if cve and cve in kev:
        return "CRITICAL"
    if cve and epss.get(cve, 0.0) >= EPSS_THRESHOLD:
        return "HIGH"
    return "DIGEST"


def build_findings(matches, kev, epss):
    """matches: {(eco,name,ver): [hydrated...]} -> list of finding dicts w/ tier.

    Deduped by (package, CVE): several OSV advisory ids (GHSA-, PYSEC-, …) can
    alias the same CVE, and we don't want to show or count it more than once.
    """
    findings = []
    seen = set()
    for (eco, name, ver), vulns in matches.items():
        for v in vulns:
            dkey = (eco, name, ver, v.get("cve") or v["id"])
            if dkey in seen:
                continue
            seen.add(dkey)
            f = {
                "ecosystem": eco, "pkg": name, "version": ver,
                "id": v["id"], "cve": v.get("cve"),
                "malicious": v.get("malicious", False),
                "summary": v.get("summary", ""),
                "epss": epss.get(v.get("cve"), None) if v.get("cve") else None,
            }
            f["tier"] = classify(f, kev, epss)
            findings.append(f)
    return findings


# -------------------------------------------------------------------- state ---
def load_state():
    f = STATE / "seen.json"
    if f.exists():
        try:
            return json.loads(f.read_text())
        except json.JSONDecodeError:
            return {}
    return {}


def save_state(state):
    STATE.mkdir(parents=True, exist_ok=True)
    (STATE / "seen.json").write_text(json.dumps(state, indent=2, sort_keys=True))


def _key(f):
    # CVE-stable so OSV returning advisory ids in a different order across runs
    # doesn't look like a new finding; falls back to the OSV id when no CVE.
    return f"{f['ecosystem']}:{f['pkg']}:{f.get('cve') or f['id']}"


def select_new_or_escalated(findings, state):
    """Keep findings unseen before, or whose tier got more severe."""
    fresh = []
    for f in findings:
        k = _key(f)
        prev = state.get(k)
        if prev is None or TIERS.get(f["tier"], 0) > TIERS.get(prev, 0):
            fresh.append(f)
    return fresh


# -------------------------------------------------------------------- alert ---
def build_alert(fresh, target):
    crit = [f for f in fresh if f["tier"] == "CRITICAL"]
    high = [f for f in fresh if f["tier"] == "HIGH"]
    digest = [f for f in fresh if f["tier"] == "DIGEST"]
    lines = [f"📡 **rush-sentry pwn watch** - `{target}`", ""]
    if crit:
        lines.append(f"🔴 **CRITICAL ({len(crit)})** - malware or actively exploited:")
        for f in sorted(crit, key=lambda x: x["id"]):
            tag = "☣️ MALICIOUS PACKAGE" if f["malicious"] else "KEV (exploited in the wild)"
            label = f["cve"] or f["id"]
            lines.append(f"• **{label}** - `{f['pkg']} {f['version']}` - {tag}")
    if high:
        lines.append("")
        lines.append(f"🟠 **HIGH ({len(high)})** - high exploit probability (EPSS ≥ {EPSS_THRESHOLD}):")
        for f in sorted(high, key=lambda x: -(x["epss"] or 0)):
            lines.append(f"• **{f['cve'] or f['id']}** - `{f['pkg']} {f['version']}` - EPSS {f['epss']:.2f}")
    if digest:
        lines.append("")
        lines.append(f"⚪ _DIGEST: {len(digest)} other new finding(s) below alert threshold._")
    lines.append("")
    lines.append("_Review before acting. Defensive/authorized use only._")
    return "\n".join(lines)


def post_webhook(url, content):
    if len(content) > 1900:
        content = content[:1890] + "\n… (truncated)"
    payload = {"content": content} if "discord" in url else {"text": content}
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return 200 <= r.status < 300
    except urllib.error.URLError as e:
        sys.stderr.write(f"[notify] webhook post failed: {e}\n")
        return False


def main():
    ap = argparse.ArgumentParser(prog="rush-sentry notify")
    ap.add_argument("--target", default=".", help="repo/dir to watch")
    ap.add_argument("--dry-run", action="store_true", help="print, do not post")
    ap.add_argument("--test", action="store_true", help="send a webhook test message")
    ap.add_argument("--all", action="store_true",
                    help="report every finding, ignoring saved state (no dedup)")
    args = ap.parse_args()
    load_env()
    webhook = os.environ.get("RUSH_SENTRY_WEBHOOK", "")

    if args.test:
        if not webhook:
            sys.stderr.write("[notify] no RUSH_SENTRY_WEBHOOK set\n")
            sys.exit(1)
        ok = post_webhook(webhook, "✅ rush-sentry pwn watch - alerts will arrive here.")
        print("ok" if ok else "failed")
        sys.exit(0 if ok else 1)

    target = str(Path(args.target).resolve())
    sys.stderr.write("[notify] building dependency inventory (syft) …\n")
    pkgs = inventory(target)
    sys.stderr.write(f"[notify] packages: {len(pkgs)}. Querying OSV …\n")
    matched = osv_match(pkgs)

    # hydrate unique vuln ids once
    cache = {}
    hydrated = {}
    for pkg, ids in matched.items():
        hydrated[pkg] = []
        for vid in ids:
            if vid not in cache:
                cache[vid] = osv_hydrate(vid)
                cache[vid]["id"] = vid
            hydrated[pkg].append(cache[vid])

    cve_ids = {h["cve"] for h in cache.values() if h.get("cve")}
    sys.stderr.write(f"[notify] vulns: {len(cache)} ({len(cve_ids)} CVEs). "
                     "Fetching KEV + EPSS …\n")
    kev = fetch_kev()
    epss = fetch_epss(cve_ids)

    findings = build_findings(hydrated, kev, epss)
    counts = {t: sum(1 for f in findings if f["tier"] == t) for t in TIERS}
    sys.stderr.write(f"[notify] findings - CRITICAL {counts['CRITICAL']}, "
                     f"HIGH {counts['HIGH']}, DIGEST {counts['DIGEST']}\n")

    state = {} if args.all else load_state()
    fresh = findings if args.all else select_new_or_escalated(findings, state)

    summary = {"target": target, "packages": len(pkgs),
               "counts": counts, "new_or_escalated": len(fresh)}

    if not fresh:
        sys.stderr.write("[notify] nothing new or escalated - quiet ✓\n")
        print(json.dumps(summary, indent=2))
        return

    alert = build_alert(fresh, target)
    if args.dry_run or not webhook:
        if not webhook and not args.dry_run:
            sys.stderr.write("[notify] no webhook; printing (dry-run)\n")
        print(alert)
    else:
        # Only ping for CRITICAL/HIGH; pure-digest runs update state silently.
        pingable = [f for f in fresh if f["tier"] in ("CRITICAL", "HIGH")]
        if pingable:
            ok = post_webhook(webhook, alert)
            sys.stderr.write(f"[notify] posted: {'ok' if ok else 'FAILED'}\n")
        else:
            sys.stderr.write("[notify] only digest-level findings; not pinging\n")
        print(json.dumps(summary, indent=2))

    # persist state for every finding seen this run
    for f in findings:
        state[_key(f)] = f["tier"]
    if not args.all:
        save_state(state)


if __name__ == "__main__":
    main()
