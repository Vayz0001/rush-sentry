"""Unit tests for notify/watch.py (PURL parsing, tier classification, dedup)."""
import importlib.util
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _load(relpath, name):
    spec = importlib.util.spec_from_file_location(name, REPO / relpath)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


watch = _load("notify/watch.py", "watch")


# -------------------------------------------------------------------- parse_purl
def test_parse_purl_basic():
    assert watch.parse_purl("pkg:pypi/jinja2@2.4.1") == ("PyPI", "jinja2", "2.4.1")
    assert watch.parse_purl("pkg:npm/left-pad@1.0.0") == ("npm", "left-pad", "1.0.0")


def test_parse_purl_strips_qualifiers():
    assert watch.parse_purl("pkg:pypi/requests@2.0.0?arch=x86") == ("PyPI", "requests", "2.0.0")


def test_parse_purl_keeps_namespaced_name():
    assert watch.parse_purl("pkg:golang/github.com/foo/bar@v1.2.3") == (
        "Go", "github.com/foo/bar", "v1.2.3")


def test_parse_purl_rejects_bad_input():
    assert watch.parse_purl("") is None
    assert watch.parse_purl(None) is None
    assert watch.parse_purl("jinja2@2.4.1") is None          # missing pkg: scheme
    assert watch.parse_purl("pkg:pypi/noversion") is None     # no @version
    assert watch.parse_purl("pkg:unknowneco/x@1") is None     # unmapped ecosystem


# ---------------------------------------------------------------------- classify
def test_classify_malicious_is_critical():
    assert watch.classify({"malicious": True, "cve": None}, set(), {}) == "CRITICAL"


def test_classify_kev_is_critical():
    f = {"malicious": False, "cve": "CVE-2021-44228"}
    assert watch.classify(f, {"CVE-2021-44228"}, {}) == "CRITICAL"


def test_classify_high_when_epss_at_or_above_threshold():
    f = {"malicious": False, "cve": "CVE-2020-0001"}
    assert watch.classify(f, set(), {"CVE-2020-0001": 0.9}) == "HIGH"
    # exactly at threshold also qualifies
    at = {"malicious": False, "cve": "CVE-2020-0003"}
    assert watch.classify(at, set(), {"CVE-2020-0003": watch.EPSS_THRESHOLD}) == "HIGH"


def test_classify_digest_below_threshold_or_no_cve():
    below = {"malicious": False, "cve": "CVE-2020-0002"}
    assert watch.classify(below, set(), {"CVE-2020-0002": 0.01}) == "DIGEST"
    assert watch.classify({"malicious": False, "cve": None}, set(), {}) == "DIGEST"


# ----------------------------------------------------------------- build_findings
def test_build_findings_dedupes_aliased_cve():
    matches = {("PyPI", "jinja2", "2.4.1"): [
        {"id": "GHSA-aaaa", "cve": "CVE-2020-1234", "malicious": False},
        {"id": "PYSEC-2020-1", "cve": "CVE-2020-1234", "malicious": False},  # same CVE, alias id
        {"id": "GHSA-bbbb", "cve": "CVE-2020-9999", "malicious": False},
    ]}
    out = watch.build_findings(matches, set(), {})
    assert sorted(f["cve"] for f in out) == ["CVE-2020-1234", "CVE-2020-9999"]
    assert len(out) == 2  # the duplicate CVE collapsed to one finding


def test_build_findings_assigns_tier():
    matches = {("npm", "evil", "1.0.0"): [{"id": "MAL-1", "cve": None, "malicious": True}]}
    out = watch.build_findings(matches, set(), {})
    assert out[0]["tier"] == "CRITICAL"


# ------------------------------------------------------------------------- _key
def test_key_is_cve_stable_across_advisory_ids():
    f1 = {"ecosystem": "PyPI", "pkg": "jinja2", "cve": "CVE-2020-1234", "id": "GHSA-aaaa"}
    f2 = {"ecosystem": "PyPI", "pkg": "jinja2", "cve": "CVE-2020-1234", "id": "PYSEC-xxxx"}
    assert watch._key(f1) == watch._key(f2)


def test_key_falls_back_to_id_without_cve():
    f = {"ecosystem": "npm", "pkg": "evil", "cve": None, "id": "MAL-1"}
    assert watch._key(f) == "npm:evil:MAL-1"
