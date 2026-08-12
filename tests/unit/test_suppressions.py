"""Suppressions loader + apply + expired-rule findings."""

import datetime
import subprocess
from pathlib import Path

import pytest

from secure_code_audit.findings import Category, Confidence, Finding, Severity
from secure_code_audit.suppressions import apply, expired_findings, load


def _f(rule_id="B608", file_path=Path("a.py")):
    return Finding(
        rule_id=rule_id,
        scanner="bandit",
        fingerprint="x",
        canonical_cwe="CWE-89",
        owasp_top10="A03",
        asvs_section=None,
        nist_ssdf=None,
        category=Category.CODE_VULNERABILITIES,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        file_path=file_path,
        line_start=1,
        line_end=None,
        code_snippet=None,
        message="m",
    )


def _write(path: Path, content: str):
    path.write_text(content, encoding="utf-8")


def test_missing_file_yields_no_rules(tmp_path):
    rules, errors = load(tmp_path / "missing.yaml")
    assert rules == []
    assert errors == []


def test_reason_required(tmp_path):
    p = tmp_path / ".scignore.yaml"
    _write(p, "- rule_id: B608\n  expires: '2099-01-01'\n  reason: ''\n")
    _, errors = load(p)
    assert errors
    assert any("reason" in e for e in errors)


def test_expires_required(tmp_path):
    p = tmp_path / ".scignore.yaml"
    _write(p, "- rule_id: B608\n  reason: 'r'\n")
    _, errors = load(p)
    assert errors
    assert any("expires" in e for e in errors)


def test_max_ttl_enforced(tmp_path):
    far = (datetime.date.today() + datetime.timedelta(days=400)).isoformat()
    p = tmp_path / ".scignore.yaml"
    _write(p, f"- rule_id: B608\n  reason: 'r'\n  expires: '{far}'\n")
    _, errors = load(p)
    assert errors
    assert any("days" in e for e in errors)


def test_wildcard_requires_file_or_paths(tmp_path):
    p = tmp_path / ".scignore.yaml"
    _write(p, "- rule_id: '*'\n  reason: 'too broad'\n  expires: '2099-01-01'\n")
    _, errors = load(p)
    assert errors
    assert any("file" in e or "paths" in e for e in errors)


def test_apply_suppresses_matching_rule(tmp_path):
    near = (datetime.date.today() + datetime.timedelta(days=30)).isoformat()
    p = tmp_path / ".scignore.yaml"
    _write(p, f"- rule_id: B608\n  reason: 'known'\n  expires: '{near}'\n")
    rules, errors = load(p)
    assert not errors
    out = apply([_f()], rules)
    assert out[0].suppressed is True
    assert "known" in out[0].suppression_note


def test_apply_does_not_suppress_expired(tmp_path):
    past = (datetime.date.today() - datetime.timedelta(days=1)).isoformat()
    p = tmp_path / ".scignore.yaml"
    _write(p, f"- rule_id: B608\n  reason: 'stale'\n  expires: '{past}'\n")
    rules, _ = load(p)
    out = apply([_f()], rules)
    assert out[0].suppressed is False


def test_expired_findings_emit_critical(tmp_path):
    past = (datetime.date.today() - datetime.timedelta(days=10)).isoformat()
    p = tmp_path / ".scignore.yaml"
    _write(p, f"- rule_id: B608\n  reason: 'shipped late'\n  expires: '{past}'\n")
    rules, _ = load(p)
    expired = expired_findings(rules, p)
    assert len(expired) == 1
    assert expired[0].severity is Severity.CRITICAL


def test_a_present_but_unloadable_suppression_file_fails_the_run(tmp_path, capsys):
    """An unusable suppression file must stop the run, not warn and continue.

    A suppression file that exists is an explicit instruction. Ignoring it
    silently changes which findings are reported, and "my suppressions
    applied" then looks identical to "my suppressions were skipped". This
    happened for real: PyYAML was missing, so an entire .scignore.yaml was
    a no-op while the run exited 0 and reported the suppressed finding as
    live. The warning was on stderr and scrolled past unread.
    """
    from secure_code_audit.cli import main

    # A git repo, because suppressions resolve against the repository root
    # rather than the scan target.
    subprocess.run(["git", "init", "-q", "."], cwd=tmp_path, check=True, capture_output=True)
    (tmp_path / "a.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    (tmp_path / ".scignore.yaml").write_text("not: valid: yaml: [\n", encoding="utf-8")

    code = main([str(tmp_path), "--json-output", str(tmp_path / "out.json")])

    assert code == 1
    assert "could not be applied" in capsys.readouterr().err


def test_no_suppression_file_is_not_an_error(tmp_path):
    """Repositories that use no suppressions are unaffected by the above."""
    from secure_code_audit.cli import main

    subprocess.run(["git", "init", "-q", "."], cwd=tmp_path, check=True, capture_output=True)
    (tmp_path / "a.py").write_text("def f():\n    return 1\n", encoding="utf-8")

    assert main([str(tmp_path), "--json-output", str(tmp_path / "out.json")]) == 0


# --- identity at the real scanner boundary -----------------------------------------


def _gitleaks_findings(*lines: int):
    """Findings built by the production gitleaks adapter, not hand-made fingerprints.

    The previous version of these tests invented fingerprints and asserted against them, which
    proved the matcher worked on values that could never occur. It missed that the adapter
    produces IDENTICAL fingerprints for different secrets: make_fingerprint excludes the line so
    reformatting cannot break baseline identity, and gitleaks reports REDACTED evidence.
    """
    from pathlib import Path

    from secure_code_audit.scanners.gitleaks_scanner import GitleaksScanner

    scanner = GitleaksScanner.__new__(GitleaksScanner)
    hits = [
        {
            "RuleID": "generic-api-key",
            "File": "api/tests/x.py",
            "StartLine": n,
            "Match": "key = REDACTED",
            "Description": "Generic API Key",
        }
        for n in lines
    ]
    return scanner._parse(hits, Path("."))


def test_two_distinct_secrets_share_a_fingerprint_at_the_real_boundary():
    """Pins the property that makes `fingerprint` alone insufficient. If this ever stops being
    true, the guidance in the schema docs needs revisiting — it is not a bug, it is why `line`
    exists."""
    first, second = _gitleaks_findings(18, 999)
    assert first.fingerprint == second.fingerprint
    assert first.line_start != second.line_start


def test_a_fingerprint_and_line_pinned_entry_suppresses_only_its_own_finding():
    import datetime

    from secure_code_audit.suppressions import SuppressionRule

    first, second = _gitleaks_findings(18, 999)
    rule = SuppressionRule(
        rule_id="gitleaks.generic-api-key",
        reason="deliberate test canary",
        expires=datetime.date(2099, 1, 1),
        file="api/tests/x.py",
        fingerprint=first.fingerprint,
        line=18,
    )
    assert rule.matches(first) is True
    assert rule.matches(second) is False


def test_a_fingerprint_only_entry_still_covers_a_second_secret():
    """Honest about the residual: without `line`, the collision above means a second secret in
    the same file is still suppressed. Documented so the narrow form is chosen knowingly."""
    import datetime

    from secure_code_audit.suppressions import SuppressionRule

    first, second = _gitleaks_findings(18, 999)
    rule = SuppressionRule(
        rule_id="gitleaks.generic-api-key",
        reason="r",
        expires=datetime.date(2099, 1, 1),
        file="api/tests/x.py",
        fingerprint=first.fingerprint,
    )
    assert rule.matches(second) is True


# --- malformed configuration must fail closed --------------------------------------


def _load_entry(tmp_path, extra: str):
    from secure_code_audit.suppressions import load

    path = tmp_path / "s.yaml"
    path.write_text(
        "- file: a/b.py\n"
        "  rule_id: gitleaks.generic-api-key\n"
        "  reason: r\n"
        "  expires: 2027-01-01\n"
        f"  {extra}\n",
        encoding="utf-8",
    )
    return load(path)


@pytest.mark.parametrize(
    "extra",
    [
        'fingerprint: ""',  # empty
        "fingerprint: 0",  # not 16 hex
        "fingerprint: NOTHEXNOTHEX",  # wrong alphabet
        "fingerpint: 0aaa689f8a967d8c",  # typo — previously ignored, silently widening the entry
        'line: "abc"',  # wrong type
        "line: 0",  # not a real line
        "line: true",  # bool is not an int here
        "unexpected: value",  # unknown field
    ],
)
def test_malformed_or_unknown_fields_are_rejected_not_ignored(tmp_path, extra):
    rules, errors = _load_entry(tmp_path, extra)
    assert rules == [], f"{extra!r} produced a usable rule"
    assert errors, f"{extra!r} was silently accepted"


def test_a_well_formed_narrow_entry_loads(tmp_path):
    rules, errors = _load_entry(tmp_path, "fingerprint: 0aaa689f8a967d8c\n  line: 18")
    assert errors == []
    assert rules[0].fingerprint == "0aaa689f8a967d8c" and rules[0].line == 18
