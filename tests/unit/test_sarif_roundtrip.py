"""SARIF emit → ingest roundtrip — the schema we promise to consumers."""

import json
from pathlib import Path

from secure_code_audit import sarif
from secure_code_audit.findings import (
    Category,
    Confidence,
    Finding,
    Severity,
)


def _f(rule_id="bandit.B608", severity=Severity.HIGH):
    return Finding(
        rule_id=rule_id,
        scanner="bandit",
        fingerprint=Finding.make_fingerprint(
            canonical_cwe="CWE-89",
            rule_id=rule_id,
            file_path=Path("a.py"),
            code_snippet="select * from x",
        ),
        canonical_cwe="CWE-89",
        owasp_top10="A03",
        asvs_section="V5.3.5",
        nist_ssdf="PW.5.1",
        category=Category.CODE_VULNERABILITIES,
        severity=severity,
        confidence=Confidence.HIGH,
        file_path=Path("a.py"),
        line_start=5,
        line_end=5,
        code_snippet="select * from x",
        message="possible SQLi",
        cwe_top25=True,
    )


def test_emit_contains_required_sarif_fields():
    doc = sarif.emit([_f()])
    assert doc["version"] == "2.1.0"
    assert "$schema" in doc
    assert "runs" in doc and len(doc["runs"]) == 1
    run = doc["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "secure-code-agent"
    assert any(r["id"] == "bandit.B608" for r in driver["rules"])
    assert run["results"][0]["ruleId"] == "bandit.B608"
    assert run["results"][0]["fingerprints"]["secure-code-agent/v1"]


def test_emit_severity_mapping():
    doc = sarif.emit([_f(severity=Severity.HIGH), _f(rule_id="x", severity=Severity.LOW)])
    levels = [r["level"] for r in doc["runs"][0]["results"]]
    assert "error" in levels
    assert "note" in levels


def test_roundtrip_via_temp_file(tmp_path):
    out = tmp_path / "out.sarif"
    findings = [_f()]
    sarif.write(findings, out)
    assert out.exists()
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["version"] == "2.1.0"

    re_ingested = sarif.ingest(out)
    assert re_ingested
    assert re_ingested[0].canonical_cwe == "CWE-89"


def test_ingest_handles_missing_file(tmp_path):
    assert sarif.ingest(tmp_path / "missing.sarif") == []


def test_ingest_handles_malformed_json(tmp_path):
    p = tmp_path / "bad.sarif"
    p.write_text("{not json", encoding="utf-8")
    assert sarif.ingest(p) == []
