from secure_code_audit.standards import (
    CWE_TOP25_2025,
    cwe_url,
    is_top25,
    lookup,
    owasp_label,
)


def test_top25_set_contains_known_entries():
    assert "CWE-89" in CWE_TOP25_2025  # SQL injection
    assert "CWE-79" in CWE_TOP25_2025  # XSS
    assert "CWE-798" in CWE_TOP25_2025  # hardcoded creds


def test_is_top25_handles_none():
    assert is_top25(None) is False


def test_is_top25_match():
    assert is_top25("CWE-89") is True
    assert is_top25("CWE-9999") is False


def test_cwe_url_generates_mitre_link():
    assert cwe_url("CWE-89") == "https://cwe.mitre.org/data/definitions/89.html"


def test_lookup_exact_match():
    entry = lookup("bandit", "B608")
    assert entry is not None
    assert entry.canonical_cwe == "CWE-89"


def test_lookup_wildcard_fallback():
    # pip_audit registers only ("pip_audit", "*") — any rule_id resolves.
    entry = lookup("pip_audit", "GHSA-anything")
    assert entry is not None
    assert entry.canonical_cwe == "CWE-1104"


def test_lookup_unknown_returns_none():
    assert lookup("unknown_scanner", "X") is None


def test_owasp_label_resolves_bucket():
    assert "Injection" in owasp_label("A03")
    assert "Broken Access Control" in owasp_label("A01")
    # Unknown id → unchanged
    assert owasp_label("Z99") == "Z99"
