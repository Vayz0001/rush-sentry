#!/usr/bin/env python3
"""Enrich a SARIF 2.1.0 stream (stdin -> stdout). Stdlib only.

Two additions that make findings far more useful in a code-scanning UI:

1. security-severity: SARIF `level` has only 4 values (none/note/warning/error),
   too coarse for GitHub's crit/high/med/low banding. We attach a numeric
   `security-severity` to each referenced rule, preferring a real CVSS/score
   from the tool when present, else mapping from `level`. GitHub bands:
   >=9.0 critical, 7.0-8.9 high, 4.0-6.9 medium, 0.1-3.9 low.

2. partialFingerprints.primaryLocationLineHash: a stable per-finding hash so the
   platform can dedup across runs and track a finding as code moves - which is
   what makes "only new findings fail the build" reliable. Important here because
   we merge several tools into one combined.sarif.

Input that isn't valid JSON is passed through unchanged (fail-open).
"""
import sys
import json
import hashlib

LEVEL_SEV = {"error": "8.0", "warning": "5.0", "note": "3.0", "none": "1.0"}
# keys a tool might stash a real score under, on the result or its rule
SCORE_KEYS = ("security-severity", "cvssScore", "cvss_score", "cvss")


def _num(v):
    try:
        return str(float(v))
    except (TypeError, ValueError):
        return None


def severity_for(result, rule):
    props = (rule or {}).get("properties", {}) or {}
    for k in SCORE_KEYS:
        if k in props:
            n = _num(props[k])
            if n is not None:
                return n
    rp = result.get("properties", {}) or {}
    for k in SCORE_KEYS:
        if k in rp:
            n = _num(rp[k])
            if n is not None:
                return n
    return LEVEL_SEV.get(result.get("level", "warning"), "5.0")


def fingerprint(result):
    loc = (result.get("locations") or [{}])[0]
    phys = loc.get("physicalLocation", {}) or {}
    region = phys.get("region", {}) or {}
    uri = (phys.get("artifactLocation", {}) or {}).get("uri", "")
    line = str(region.get("startLine", ""))
    rid = result.get("ruleId", "")
    snippet = (region.get("snippet", {}) or {}).get("text", "")
    raw = "\x1f".join([uri, line, rid, snippet]).encode("utf-8", "replace")
    return hashlib.sha256(raw).hexdigest()


def enrich(data):
    for run in data.get("runs", []) or []:
        driver = run.get("tool", {}).get("driver", {})
        rules = driver.setdefault("rules", [])
        by_id = {r.get("id"): r for r in rules if isinstance(r, dict)}
        for res in run.get("results", []) or []:
            rid = res.get("ruleId")
            rule = by_id.get(rid)
            if rule is None and rid is not None:
                rule = {"id": rid, "properties": {}}
                rules.append(rule)
                by_id[rid] = rule
            sev = severity_for(res, rule)
            if rule is not None:
                rule.setdefault("properties", {})["security-severity"] = sev
            res.setdefault("partialFingerprints", {})["primaryLocationLineHash"] = fingerprint(res)
    return data


def main():
    raw = sys.stdin.read()
    try:
        data = json.loads(raw)
    except (ValueError, json.JSONDecodeError):
        sys.stdout.write(raw)  # fail-open: pass through untouched
        return
    json.dump(enrich(data), sys.stdout)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
