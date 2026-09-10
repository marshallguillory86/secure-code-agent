"""The artifact maintainability-agent ingests, and the rules it must obey.

D3 settled that MA reads a `security-pillar.json` this tool writes rather than
MA executing this tool. That makes the document a contract between two
codebases, and the properties below are the contract — not implementation
details of either side.

Everything structural is MA's: the scope vocabulary, the two-axis split, the
posture matrix and its thresholds. Two tools reporting "level 3" or "healthy"
about the same repository must mean the same thing by it.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from secure_code_audit import pillar as pillar_mod
from secure_code_audit import practice as practice_mod
from secure_code_audit.findings import Category, Confidence, Finding, Severity
from secure_code_audit.scanner_status import (
    CoverageStatus,
    ScannerExecution,
    ScannerOutcome,
    evaluate_coverage,
)
from secure_code_audit.scoring import score, summarize_axis, verdict

PILLAR_SOURCE = Path(pillar_mod.__file__)


def _coverage(status: str):
    """Coverage in a given state, built through the real evaluator."""
    if status == "complete":
        return evaluate_coverage([ScannerExecution("bandit", ScannerOutcome.COMPLETED)], ["bandit"])
    return evaluate_coverage(
        [ScannerExecution("bandit", ScannerOutcome.UNAVAILABLE, reason="not installed")],
        ["bandit"],
    )


def _finding(severity: Severity) -> Finding:
    return Finding(
        rule_id="r",
        scanner="bandit",
        fingerprint="f",
        canonical_cwe="CWE-89",
        owasp_top10="A03",
        asvs_section="V5",
        nist_ssdf="PW.5.1",
        category=Category.CODE_VULNERABILITIES,
        severity=severity,
        confidence=Confidence.HIGH,
        file_path=Path("app.py"),
        line_start=1,
        line_end=1,
        code_snippet="x",
        message="m",
    )


def _build(*, findings, loc, coverage_status, level):
    report = score(findings, loc)
    gates = {"require_scanners": ["bandit"]}
    cov = _coverage(coverage_status)
    return pillar_mod.build(
        report,
        verdict(report, gates, cov),
        cov,
        practice_mod.PracticeLevel(level=level, summary="s", signals=()),
        (summarize_axis("test tree", [], loc=10), summarize_axis("dependencies", [])),
    )


# --------------------------------------------------------------------------
# The matrix — ADR 007 §2
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("level", "condition", "expected"),
    [
        (5, 5.0, "healthy"),
        (3, 3.5, "healthy"),
        (2, 5.0, "unverified"),
        (1, 4.9, "unverified"),
        (5, 2.0, "managed debt"),
        (3, 0.0, "managed debt"),
        (2, 2.0, "unmanaged debt"),
        (1, 0.0, "unmanaged debt"),
        (5, None, "unverified"),
        (1, None, "unverified"),
    ],
)
def test_posture_matches_mas_matrix(level: int, condition: float | None, expected: str):
    """MA's `_pillars.posture`, cell for cell.

    The thresholds are copied by value on purpose: if MA moves HIGH_PRACTICE or
    GOOD_CONDITION, this fails and someone has to reconcile the two tools
    rather than letting them drift into disagreeing about the same word.
    """
    assert pillar_mod.posture(level, condition) == expected


def test_perfect_practice_cannot_vouch_for_unmeasured_code():
    """The cell that matters, and the reason the split exists.

    A repository with every gate wired and no scanner able to run is not
    healthy. It is unverified — and this tool's version is sharper than MA's,
    because withholding scanners *raises* a finding-rate score rather than
    lowering it.
    """
    assert pillar_mod.posture(5, None) == "unverified"
    assert pillar_mod.posture(5, 5.0) == "healthy"


# --------------------------------------------------------------------------
# Condition is admitted only when the evidence supports it
# --------------------------------------------------------------------------


def test_condition_is_null_when_coverage_is_incomplete():
    """Absence of evidence must not arrive as a perfect score.

    Zero findings grades 5.0. If coverage failed, that 5.0 says only that
    nothing looked — handing it to MA would launder it into a pillar report
    that looks measured.
    """
    built = _build(findings=[], loc=10_000, coverage_status="failed", level=5)

    assert built.condition is None
    assert built.condition_letter is None
    assert built.posture == "unverified"
    assert built.verified_grade is None
    assert built.evidence_status == "incomplete"


def test_condition_is_present_when_coverage_is_complete():
    built = _build(findings=[], loc=10_000, coverage_status="complete", level=5)

    assert built.condition == 5.0
    assert built.condition_letter == "A+"
    assert built.posture == "healthy"
    assert built.verified_grade == "A+"
    assert built.evidence_status == "complete"


def test_withholding_scanners_cannot_improve_the_document():
    """P3, at the artifact boundary.

    The same clean finding set reports a condition under complete coverage and
    no condition under failed coverage. There is no arrangement of scanners
    that turns a worse-evidenced run into a better-looking pillar.
    """
    measured = _build(findings=[], loc=10_000, coverage_status="complete", level=5)
    unmeasured = _build(findings=[], loc=10_000, coverage_status="failed", level=5)

    assert measured.condition is not None
    assert unmeasured.condition is None
    assert unmeasured.posture != "healthy"


# --------------------------------------------------------------------------
# The document itself
# --------------------------------------------------------------------------


def test_the_document_carries_both_axes_and_never_their_mean():
    built = _build(
        findings=[_finding(Severity.HIGH)], loc=10_000, coverage_status="complete", level=4
    )

    document = pillar_mod.to_dict(built)

    assert document["schema"] == "secure-code-agent/security-pillar"
    assert document["schema_version"] == 1
    assert document["pillar"] == "security"
    assert document["scope"] == "owned"
    assert document["practice"]["level"] == 4
    assert isinstance(document["condition"], float)
    assert document["posture"] in {"healthy", "managed debt", "unmanaged debt", "unverified"}
    # No field offers the two axes combined.
    assert "overall" not in document
    assert "combined" not in document
    assert "average" not in document


def test_the_document_is_json_serialisable_and_round_trips(tmp_path):
    built = _build(findings=[], loc=100, coverage_status="complete", level=3)
    path = tmp_path / "security-pillar.json"

    pillar_mod.write(built, path)
    reloaded = json.loads(path.read_text(encoding="utf-8"))

    assert reloaded["practice"]["level"] == 3
    assert reloaded["producer"]["tool"] == "secure-code-agent"
    assert reloaded["notes"]["never_average"]


def test_the_pillar_never_averages_its_two_axes():
    """The guard MA keeps over `_pillars.py`, kept here for the same reason.

    A function combining practice and condition would reinstate exactly the
    defect the split exists to remove, and it would be an easy, reasonable
    looking thing for someone to add. So the module is parsed and refused one.
    """
    tree = ast.parse(PILLAR_SOURCE.read_text(encoding="utf-8"))

    for node in ast.walk(tree):
        if not isinstance(node, ast.BinOp):
            continue
        operands = ast.dump(node)
        combines = "practice" in operands and "condition" in operands
        assert not combines, (
            f"{PILLAR_SOURCE.name} line {node.lineno} combines practice and "
            f"condition arithmetically; ADR 007 §2 forbids it"
        )


def test_coverage_status_and_missing_scanners_reach_the_document():
    """MA has to be able to say *why* a condition was withheld."""
    built = _build(findings=[], loc=100, coverage_status="failed", level=1)

    document = pillar_mod.to_dict(built)

    assert document["coverage"]["status"] == CoverageStatus.FAILED.value
    assert "bandit" in document["coverage"]["scanners_missing"]
    assert document["evidence_reasons"], "a withheld grade must say why"
