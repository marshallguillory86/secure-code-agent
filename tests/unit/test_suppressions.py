"""Suppressions loader + apply + expired-rule findings."""

import datetime
import subprocess
from pathlib import Path

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
