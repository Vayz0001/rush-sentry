#!/usr/bin/env python3
"""rush-sentry threat-intel watcher.

Cross-references a target's vulnerable dependencies against the CISA KEV
(Known Exploited Vulnerabilities) catalog and alerts on the intersection:
"you depend on something that is being ACTIVELY EXPLOITED right now."

Pure stdlib. Defensive/authorized use only. Delivery is a Discord/Slack webhook
(post-only). Reads the webhook from $RUSH_SENTRY_WEBHOOK or ./.env.
"""
import argparse, json, os, subprocess, sys, urllib.request, urllib.error
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / "notify" / "state"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
TRIVY_IMG = os.environ.get("RS_IMG_TRIVY", "aquasec/trivy:latest")


def load_env():
    env = ROOT / ".env"
    if env.exists():
        for line in env.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())


def fetch_kev():
    """Return {cveID: entry} for the whole KEV catalog (cached)."""
    STATE.mkdir(parents=True, exist_ok=True)
    cache = STATE / "kev.json"
    try:
        req = urllib.request.Request(KEV_URL, headers={"User-Agent": "rush-sentry"})
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.load(r)
        cache.write_text(json.dumps(data))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
        if cache.exists():
            sys.stderr.write(f"[notify] KEV fetch failed ({e}); using cached catalog\n")
            data = json.loads(cache.read_text())
        else:
            sys.stderr.write(f"[notify] KEV fetch failed and no cache: {e}\n")
            sys.exit(1)
    return {v["cveID"]: v for v in data.get("vulnerabilities", [])}


def scan_target_cves(target):
    """Run trivy fs (json) on target; return {cveID: {pkg, version, severity, title}}."""
    try:
        out = subprocess.run(
            ["docker", "run", "--rm", "--network", "bridge",
             "-v", f"{target}:/src:ro", "-v", f"{ROOT}/.trivycache:/root/.cache/trivy",
             TRIVY_IMG, "fs", "--quiet", "--scanners", "vuln", "--format", "json", "/src"],
            capture_output=True, text=True, timeout=300,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        sys.stderr.write(f"[notify] trivy scan failed: {e}\n")
        return {}
    cves = {}
    try:
        report = json.loads(out.stdout or "{}")
    except json.JSONDecodeError:
        return cves
    for res in report.get("Results") or []:
        for v in res.get("Vulnerabilities") or []:
            cid = v.get("VulnerabilityID", "")
            if cid.startswith("CVE-"):
                cves.setdefault(cid, {
                    "pkg": v.get("PkgName", "?"),
                    "version": v.get("InstalledVersion", "?"),
                    "severity": v.get("Severity", "?"),
                    "title": v.get("Title", ""),
                })
    return cves


def build_alert(matches, target):
    lines = [f"🔴 **rush-sentry: actively-exploited dependency alert**",
             f"Target: `{target}` — **{len(matches)}** of your dependencies are on the CISA KEV catalog (being exploited in the wild):", ""]
    for cid, info in sorted(matches.items()):
        ransom = " ⚠️ *ransomware*" if info.get("ransomware") == "Known" else ""
        lines.append(f"• **{cid}** — `{info['pkg']} {info['version']}` ({info.get('severity','?')}){ransom}")
        if info.get("kev_name"):
            lines.append(f"   ↳ {info['kev_name']}")
    lines.append("")
    lines.append("_Patch or mitigate these first. Review before acting._")
    return "\n".join(lines)


def post_webhook(url, content):
    # Discord caps content at 2000 chars; truncate safely.
    if len(content) > 1900:
        content = content[:1890] + "\n… (truncated)"
    payload = {"content": content} if "discord" in url else {"text": content}
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json",
                 # Discord returns 403 for requests without a User-Agent.
                 "User-Agent": "rush-sentry/0.1 (+https://github.com/Vayz0001/rush-sentry)"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return 200 <= r.status < 300
    except urllib.error.URLError as e:
        sys.stderr.write(f"[notify] webhook post failed: {e}\n")
        return False


def main():
    ap = argparse.ArgumentParser(prog="rush-sentry notify")
    ap.add_argument("--target", default=".", help="repo/dir to check dependencies of")
    ap.add_argument("--dry-run", action="store_true", help="print, do not post")
    ap.add_argument("--test", action="store_true", help="send a test message to the webhook")
    args = ap.parse_args()
    load_env()
    webhook = os.environ.get("RUSH_SENTRY_WEBHOOK", "")

    if args.test:
        if not webhook:
            sys.stderr.write("[notify] no RUSH_SENTRY_WEBHOOK set\n"); sys.exit(1)
        ok = post_webhook(webhook, "✅ rush-sentry webhook test — threat-intel alerts will arrive here.")
        print("ok" if ok else "failed"); sys.exit(0 if ok else 1)

    target = str(Path(args.target).resolve())
    sys.stderr.write("[notify] fetching CISA KEV catalog …\n")
    kev = fetch_kev()
    sys.stderr.write(f"[notify] KEV entries: {len(kev)}. Scanning target dependencies …\n")
    tgt = scan_target_cves(target)
    sys.stderr.write(f"[notify] target CVEs: {len(tgt)}. Intersecting with KEV …\n")

    matches = {}
    for cid, info in tgt.items():
        if cid in kev:
            info = dict(info)
            info["kev_name"] = kev[cid].get("vulnerabilityName", "")
            info["ransomware"] = kev[cid].get("knownRansomwareCampaignUse", "")
            matches[cid] = info

    if not matches:
        sys.stderr.write("[notify] no actively-exploited (KEV) dependencies found — clean ✓\n")
        print(json.dumps({"target": target, "kev_matches": 0, "matches": []}, indent=2))
        return

    alert = build_alert(matches, target)
    if args.dry_run or not webhook:
        if not webhook and not args.dry_run:
            sys.stderr.write("[notify] no webhook configured; printing (dry-run)\n")
        print(alert)
    else:
        ok = post_webhook(webhook, alert)
        sys.stderr.write(f"[notify] posted alert to webhook: {'ok' if ok else 'FAILED'}\n")
        print(json.dumps({"target": target, "kev_matches": len(matches),
                          "matches": sorted(matches)}, indent=2))


if __name__ == "__main__":
    main()
