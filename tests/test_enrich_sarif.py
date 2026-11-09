"""Unit tests for scanners/lib/enrich_sarif.py (SARIF severity + fingerprint enrichment)."""
import io
import sys
import importlib.util
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _load(relpath, name):
    spec = importlib.util.spec_from_file_location(name, REPO / relpath)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


enrich = _load("scanners/lib/enrich_sarif.py", "enrich_sarif")


def test_level_maps_to_security_severity():
    assert enrich.severity_for({"level": "error"}, None) == "8.0"
    assert enrich.severity_for({"level": "warning"}, None) == "5.0"
    assert enrich.severity_for({"level": "note"}, None) == "3.0"
    assert enrich.severity_for({"level": "none"}, None) == "1.0"
    assert enrich.severity_for({}, None) == "5.0"  # default when level absent


def test_real_cvss_score_preferred_over_level():
    rule = {"properties": {"cvssScore": 10.0}}
    # level 'note' would map to 3.0, but a real score on the rule wins
    assert enrich.severity_for({"level": "note"}, rule) == "10.0"


def test_result_level_score_used_when_rule_has_none():
    res = {"level": "warning", "properties": {"security-severity": "9.1"}}
    assert enrich.severity_for(res, {"properties": {}}) == "9.1"


def test_bad_score_falls_back_to_level():
    rule = {"properties": {"cvssScore": "not-a-number"}}
    assert enrich.severity_for({"level": "error"}, rule) == "8.0"


def test_fingerprint_stable_and_distinct():
    base = {"ruleId": "X", "locations": [{"physicalLocation": {
        "artifactLocation": {"uri": "a.py"},
        "region": {"startLine": 5, "snippet": {"text": "foo"}}}}]}
    moved = {"ruleId": "X", "locations": [{"physicalLocation": {
        "artifactLocation": {"uri": "a.py"},
        "region": {"startLine": 6, "snippet": {"text": "foo"}}}}]}
    assert enrich.fingerprint(base) == enrich.fingerprint(base)  # deterministic
    assert enrich.fingerprint(base) != enrich.fingerprint(moved)  # line change -> new hash
    assert len(enrich.fingerprint(base)) == 64  # sha256 hex digest


def test_enrich_adds_severity_and_fingerprint():
    data = {"runs": [{
        "tool": {"driver": {"name": "t", "rules": [{"id": "R1", "properties": {}}]}},
        "results": [{"ruleId": "R1", "level": "error", "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "a"}, "region": {"startLine": 1}}}]}],
    }]}
    out = enrich.enrich(data)
    rule = out["runs"][0]["tool"]["driver"]["rules"][0]
    res = out["runs"][0]["results"][0]
    assert rule["properties"]["security-severity"] == "8.0"
    assert "primaryLocationLineHash" in res["partialFingerprints"]


def test_enrich_creates_missing_rule_for_result():
    data = {"runs": [{
        "tool": {"driver": {"name": "t"}},
        "results": [{"ruleId": "NEW", "level": "warning", "locations": []}],
    }]}
    out = enrich.enrich(data)
    ids = [r["id"] for r in out["runs"][0]["tool"]["driver"]["rules"]]
    assert "NEW" in ids


def test_main_fail_open_on_bad_json(capsys, monkeypatch):
    monkeypatch.setattr(sys, "stdin", io.StringIO("not json{"))
    enrich.main()
    assert capsys.readouterr().out == "not json{"  # passed through untouched
