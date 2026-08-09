import json
from dataclasses import replace
from pathlib import Path
from subprocess import CompletedProcess

from secure_code_audit import baseline
from secure_code_audit.findings import Category, Confidence, Finding, Severity


def _finding(*, suppressed=False):
    return Finding(
        rule_id="B608",
        scanner="bandit",
        fingerprint="abc",
        canonical_cwe="CWE-89",
        owasp_top10="A03",
        asvs_section=None,
        nist_ssdf=None,
        category=Category.CODE_VULNERABILITIES,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        file_path=Path("app.py"),
        line_start=3,
        line_end=None,
        code_snippet=None,
        message="SQL injection",
        suppressed=suppressed,
    )


def test_write_load_and_mark_new_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(
        baseline.subprocess,
        "run",
        lambda *args, **kwargs: CompletedProcess(args=[], returncode=0, stdout="dev@example.com\n"),
    )
    path = tmp_path / "baseline.json"
    baseline.write(path, [_finding()], {})

    loaded = baseline.load(path)
    marked = baseline.mark_new([_finding(), replace(_finding(), fingerprint="new")], loaded)
    payload = json.loads(path.read_text(encoding="utf-8"))

    assert loaded["abc"].bumped_by == "dev@example.com"
    assert [finding.is_new for finding in marked] == [False, True]
    assert payload["operator"] == "dev@example.com"


def test_write_preserves_existing_metadata_and_skips_suppressed(tmp_path, monkeypatch):
    existing_path = tmp_path / "baseline.json"
    existing_path.write_text(
        json.dumps(
            {
                "entries": {
                    "abc": {
                        "rule_id": "B608",
                        "severity": "high",
                        "category": "code_vulnerabilities",
                        "file_path": "app.py",
                        "first_seen": "2020-01-01T00:00:00Z",
                        "bumped_by": "first@example.com",
                        "notes": "accepted",
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    existing = baseline.load(existing_path)
    monkeypatch.setattr(
        baseline.subprocess,
        "run",
        lambda *args, **kwargs: CompletedProcess(
            args=[], returncode=0, stdout="second@example.com"
        ),
    )

    baseline.write(
        existing_path,
        [_finding(), replace(_finding(), fingerprint="skip", suppressed=True)],
        existing,
    )
    payload = json.loads(existing_path.read_text(encoding="utf-8"))

    assert payload["entries"]["abc"]["bumped_by"] == "first@example.com"
    assert "skip" not in payload["entries"]


def test_load_malformed_and_git_lookup_failure(tmp_path, monkeypatch):
    path = tmp_path / "bad.json"
    path.write_text("not json", encoding="utf-8")
    monkeypatch.setattr(
        baseline.subprocess,
        "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(FileNotFoundError()),
    )

    assert baseline.load(path) == {}
    assert baseline._git_user_email() == "unknown"
