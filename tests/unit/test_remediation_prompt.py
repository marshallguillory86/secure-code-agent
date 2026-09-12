"""Bounded remediation prompt — the differentiator. Verify every documented
hard constraint appears verbatim, and that finding context is properly
injected."""

from pathlib import Path

from secure_code_audit.findings import (
    Category,
    Confidence,
    Finding,
    Severity,
)
from secure_code_audit.remediation import generate


def _f(severity=Severity.HIGH, rule_id="B608"):
    return Finding(
        rule_id=rule_id,
        scanner="bandit",
        fingerprint="x",
        canonical_cwe="CWE-89",
        owasp_top10="A03",
        asvs_section="V5.3.5",
        nist_ssdf="PW.5.1",
        category=Category.CODE_VULNERABILITIES,
        severity=severity,
        confidence=Confidence.HIGH,
        file_path=Path("dashboard/api.py"),
        line_start=42,
        line_end=44,
        code_snippet="cursor.execute(f'SELECT * FROM u WHERE id = {uid}')",
        message="String-built SQL — possible injection.",
        short_desc="String-built SQL — possible injection.",
        fix_hint="Use parameterized queries ($1, ?, :name).",
        cwe_top25=True,
    )


def test_prompt_includes_all_hard_constraints():
    prompt = generate([_f()])
    # The ten hard constraints we promise (see docs/remediation.md).
    for clause in (
        "Fix only the findings",
        "crypto algorithms",
        "auth flows",
        "weaken validation",
        "disable, delete or skip security tests",
        "silence warnings",
        "Do not add dependencies",
        "Preserve behaviour",
        "focused test",
        "Keep the patch small",
    ):
        assert clause in prompt, f"missing constraint clause: {clause!r}"


def test_prompt_injects_cwe_owasp_asvs():
    prompt = generate([_f()])
    assert "CWE-89" in prompt
    assert "A03" in prompt
    assert "V5.3.5" in prompt
    assert "PW.5.1" in prompt


def test_prompt_renders_code_snippet():
    prompt = generate([_f()])
    assert "cursor.execute(f'SELECT" in prompt


def test_prompt_marks_top25():
    prompt = generate([_f()])
    assert "Top 25" in prompt


def test_prompt_sorts_critical_first():
    high = _f(severity=Severity.HIGH, rule_id="A")
    crit = _f(severity=Severity.CRITICAL, rule_id="B")
    prompt = generate([high, crit])
    # The CRITICAL block must appear before the HIGH block.
    assert prompt.index("1. `B`") < prompt.index("2. `A`")


def test_prompt_no_findings_message():
    prompt = generate([])
    assert "no actionable" in prompt.lower()


def test_prompt_omits_informational_findings():
    info = _f(severity=Severity.INFORMATIONAL, rule_id="info")
    prompt = generate([info])
    assert "no actionable" in prompt.lower()


def test_prompt_omits_suppressed_findings():
    from dataclasses import replace

    f = _f()
    f = replace(f, suppressed=True, suppression_note="acknowledged")
    prompt = generate([f])
    assert "no actionable" in prompt.lower()
