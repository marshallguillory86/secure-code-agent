# ---------------------------------------------------------------------------
# Suppression, in the field consumers actually read
# ---------------------------------------------------------------------------


def _finding(**kw):
    from pathlib import Path

    from secure_code_audit.findings import Category, Confidence, Finding, Severity

    base = {
        "rule_id": "B602",
        "scanner": "bandit",
        "fingerprint": "fp1",
        "canonical_cwe": "CWE-78",
        "owasp_top10": "A03",
        "asvs_section": None,
        "nist_ssdf": None,
        "category": Category.CODE_VULNERABILITIES,
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "file_path": Path("src/app.py"),
        "line_start": 1,
        "line_end": 1,
        "code_snippet": None,
        "message": "m",
    }
    base.update(kw)
    return Finding(**base)


def test_a_primary_finding_raises_an_alert():
    from secure_code_audit.sarif import emit

    (result,) = emit([_finding()])["runs"][0]["results"]

    assert "suppressions" not in result


def test_an_operator_suppression_reaches_sarif(tmp_path):
    """`properties.suppressed` is a field of our own invention that no
    consumer reads, so a finding the operator had suppressed in
    `.scignore.yaml` — with a reason and an expiry — still became an alert.
    """
    from secure_code_audit.sarif import emit

    finding = _finding(suppressed=True, suppression_note="reviewed: test double")
    (result,) = emit([finding])["runs"][0]["results"]

    assert result["suppressions"][0]["kind"] == "external"
    assert "test double" in result["suppressions"][0]["justification"]


def test_a_test_tree_finding_does_not_raise_an_alert():
    """Auditing maintainability-agent produced 4,929 SARIF results of which
    4,847 were test fixtures. Uploaded to code scanning that is 4,847 alerts
    for deliberately-vulnerable test data, burying the 82 findings in the
    shipped source."""
    from secure_code_audit.sarif import emit

    document = emit([_finding()], None, lambda _f: "test tree")
    (result,) = document["runs"][0]["results"]

    assert result["suppressions"][0]["kind"] == "external"
    assert "test tree" in result["suppressions"][0]["justification"]


def test_a_documentation_finding_does_not_raise_an_alert():
    from secure_code_audit.sarif import emit

    (result,) = emit([_finding()], None, lambda _f: "documentation")["runs"][0]["results"]

    assert result.get("suppressions")


def test_suppressed_findings_are_still_present_in_the_document():
    """Suppressed, not omitted. Nothing is hidden from a reader; it simply
    does not become someone's ticket."""
    from secure_code_audit.sarif import emit

    document = emit([_finding()], None, lambda _f: "test tree")
    (result,) = document["runs"][0]["results"]

    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/app.py"
    assert result["properties"]["axis"] == "test tree"
