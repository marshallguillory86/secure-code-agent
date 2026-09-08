"""Scoring + gate evaluation.

Implements the model documented in docs/scoring.md:
  · finding_score = severity × confidence × category × top25_bonus
  · category_subtotal = Σ finding_score per category
  · category_normalized = subtotal / sqrt(LOC / 1000)
  · category_grade = clamp(5.0 - (normalized × 0.5), 0, 5)
  · overall = min(category_grades)
"""

from __future__ import annotations

import math
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from secure_code_audit.findings import Category, Confidence, Finding, Severity
from secure_code_audit.scanner_status import CoverageReport, CoverageStatus

# --- weights ---------------------------------------------------------------

SEVERITY_WEIGHT: dict[Severity, float] = {
    Severity.CRITICAL: 10.0,
    Severity.HIGH: 4.0,
    Severity.MEDIUM: 1.5,
    Severity.LOW: 0.5,
    Severity.INFORMATIONAL: 0.0,
}

CONFIDENCE_WEIGHT: dict[Confidence, float] = {
    Confidence.HIGH: 1.00,
    Confidence.MEDIUM: 0.75,
    Confidence.LOW: 0.50,
}

CATEGORY_WEIGHT: dict[Category, float] = {
    Category.SECRETS: 1.5,
    Category.CODE_VULNERABILITIES: 1.5,
    Category.AUTH_AUTHZ: 1.5,
    Category.CRYPTO: 1.5,
    Category.DEPENDENCIES: 1.0,
    Category.CONFIG_IAC: 1.0,
    Category.SUPPLY_CHAIN: 0.8,
    Category.LOGGING_OBSERVABILITY: 0.8,
    Category.POLICY_DOCS: 0.5,
}

CWE_TOP25_BONUS = 1.25


# --- letter-grade boundaries (mirrors maintainability-agent) ---------------

_LETTER_GRADE_TABLE = (
    (4.85, "A+"),
    (4.50, "A"),
    (4.00, "A-"),
    (3.50, "B+"),
    (3.00, "B"),
    (2.50, "B-"),
    (2.00, "C"),
    (1.00, "D"),
)


def letter_grade(score: float) -> str:
    for threshold, grade in _LETTER_GRADE_TABLE:
        if score >= threshold:
            return grade
    return "F"


# --- per-finding score -----------------------------------------------------


def finding_score(f: Finding) -> float:
    """Score one finding per the documented formula. Suppressed findings
    score 0 (they're excluded by the caller before this normally fires,
    but the defensive check is cheap)."""
    if f.suppressed:
        return 0.0
    base = (
        SEVERITY_WEIGHT[f.severity] * CONFIDENCE_WEIGHT[f.confidence] * CATEGORY_WEIGHT[f.category]
    )
    if f.cwe_top25:
        base *= CWE_TOP25_BONUS
    return base


# --- per-category aggregation ---------------------------------------------


def category_subtotal(findings: Iterable[Finding], category: Category) -> float:
    return sum(finding_score(f) for f in findings if f.category == category and not f.suppressed)


def normalize(subtotal: float, loc_scanned: int) -> float:
    """sqrt(LOC/1000) dampener — see docs/scoring.md for the rationale."""
    if loc_scanned <= 0:
        return subtotal
    return subtotal / math.sqrt(max(loc_scanned, 1) / 1000)


def category_grade(normalized: float) -> float:
    return max(0.0, min(5.0, 5.0 - (normalized * 0.5)))


# --- overall score ---------------------------------------------------------


@dataclass(frozen=True)
class ScoreReport:
    """Per-category + overall score breakdown. Renderers consume this directly."""

    per_category: dict[Category, float]  # category → 0.0-5.0 grade
    per_category_count: dict[Category, int]  # category → unsuppressed finding count
    per_severity_count: dict[Severity, int]  # severity → unsuppressed finding count
    overall: float  # 0.0-5.0
    letter: str  # A+, A, A-, B+, ...
    worst_category: Category | None  # which category drove the grade
    loc_scanned: int  # for the report header

    def as_table(self) -> list[tuple[str, str, float, int]]:
        """[(category_name, grade_letter, grade_score, finding_count), ...]
        sorted worst → best for the operator report."""
        rows = []
        for cat in Category:
            grade = self.per_category.get(cat, 5.0)
            count = self.per_category_count.get(cat, 0)
            rows.append((cat.value, letter_grade(grade), grade, count))
        rows.sort(key=lambda r: r[2])  # worst first
        return rows


def score(findings: Iterable[Finding], loc_scanned: int) -> ScoreReport:
    findings = list(findings)
    per_category: dict[Category, float] = {}
    per_category_count: dict[Category, int] = {}
    per_severity_count: dict[Severity, int] = dict.fromkeys(Severity, 0)

    for cat in Category:
        subtotal = category_subtotal(findings, cat)
        normalized = normalize(subtotal, loc_scanned)
        per_category[cat] = category_grade(normalized)
        per_category_count[cat] = sum(1 for f in findings if f.category == cat and not f.suppressed)

    for f in findings:
        if not f.suppressed:
            per_severity_count[f.severity] += 1

    worst_category = min(per_category.items(), key=lambda kv: kv[1])[0] if findings else None

    overall = min(per_category.values()) if per_category else 5.0
    return ScoreReport(
        per_category=per_category,
        per_category_count=per_category_count,
        per_severity_count=per_severity_count,
        overall=overall,
        letter=letter_grade(overall),
        worst_category=worst_category,
        loc_scanned=loc_scanned,
    )


# --- gate evaluation -------------------------------------------------------


@dataclass(frozen=True)
class GateResult:
    passed: bool
    reasons: tuple[str, ...]  # human-readable trip reasons
    tripped: tuple[str, ...] = field(default_factory=tuple)


# Every gate, with the predicate that decides whether it can actually trip.
# A key that is present but inert provides no security floor: an empty
# severity list matches nothing, an empty cap map caps nothing, and no score
# can fall below a min_score of 0. Treating those as "configured" is how an
# empty policy passes for a real one.
_GATE_ACTIVATION: tuple[tuple[str, Callable[[Any], bool]], ...] = (
    ("fail_on_severity", bool),
    ("fail_on_category", bool),
    ("fail_on_new", bool),
    ("min_score", lambda v: isinstance(v, (int, float)) and v > 0),
    ("require_scanners", bool),
    ("max_unsuppressed", bool),
)


def active_gates(gate_config: dict) -> tuple[str, ...]:
    """Names of gates that can actually fail the build.

    `evaluate_gates` treats an absent gate as "not configured", which is
    correct for evaluation but means a config with no gates at all yields
    `passed=True` no matter what was found. Callers that promise to fail on
    a tripped gate use this to refuse that arrangement up front.
    """
    return tuple(name for name, is_active in _GATE_ACTIVATION if is_active(gate_config.get(name)))


def evaluate_gates(
    findings: list[Finding],
    report: ScoreReport,
    gate_config: dict,
    coverage: CoverageReport | None = None,
) -> GateResult:
    """Apply the configured gates. Any tripped gate → passed=False.

    gate_config is the `gates` block of the loaded config. See
    secure-code-agent.schema.json for shape; missing keys are treated
    as 'gate not configured' (i.e. doesn't trip)."""

    reasons: list[str] = []
    tripped: list[str] = []

    for check in (
        _gate_fail_on_severity,
        _gate_fail_on_category,
        _gate_fail_on_new,
        _gate_min_score,
        _gate_max_unsuppressed,
    ):
        check(findings, report, gate_config, tripped, reasons)

    if coverage is not None and coverage.status is CoverageStatus.FAILED:
        tripped.append("require_scanners")
        reasons.append("; ".join(coverage.failures))

    return GateResult(
        passed=not tripped,
        reasons=tuple(reasons),
        tripped=tuple(tripped),
    )


# ----- per-gate evaluators -------------------------------------------------
# Each appends to the shared `tripped` and `reasons` lists. Splitting these
# keeps evaluate_gates() at cognitive complexity <= 15 (we ship the
# maintainability standard and dogfood it here).


def _gate_fail_on_severity(
    findings: list[Finding],
    report: ScoreReport,
    gate_config: dict,
    tripped: list[str],
    reasons: list[str],
) -> None:
    fail_on = {s.lower() for s in gate_config.get("fail_on_severity", [])}
    if not fail_on:
        return
    offenders = [f for f in findings if not f.suppressed and f.severity.value in fail_on]
    if offenders:
        tripped.append("fail_on_severity")
        reasons.append(f"{len(offenders)} finding(s) at severity in {sorted(fail_on)}")


def _gate_fail_on_category(
    findings: list[Finding],
    report: ScoreReport,
    gate_config: dict,
    tripped: list[str],
    reasons: list[str],
) -> None:
    fail_cats = {c.lower() for c in gate_config.get("fail_on_category", [])}
    if not fail_cats:
        return
    offenders = [f for f in findings if not f.suppressed and f.category.value in fail_cats]
    if offenders:
        tripped.append("fail_on_category")
        reasons.append(f"{len(offenders)} finding(s) in categories {sorted(fail_cats)}")


def _gate_fail_on_new(
    findings: list[Finding],
    report: ScoreReport,
    gate_config: dict,
    tripped: list[str],
    reasons: list[str],
) -> None:
    # Informational findings (tool_unavailable, parse errors, etc.) never
    # trip the gate — they're awareness signals, not security defects.
    if not gate_config.get("fail_on_new"):
        return
    new_findings = [
        f
        for f in findings
        if f.is_new and not f.suppressed and f.severity is not Severity.INFORMATIONAL
    ]
    if new_findings:
        tripped.append("fail_on_new")
        reasons.append(f"{len(new_findings)} new finding(s) since baseline")


def _gate_min_score(
    findings: list[Finding],
    report: ScoreReport,
    gate_config: dict,
    tripped: list[str],
    reasons: list[str],
) -> None:
    min_score = gate_config.get("min_score")
    if min_score is None or report.overall >= min_score:
        return
    tripped.append("min_score")
    reasons.append(f"overall score {report.overall:.2f} below required minimum {min_score}")


def _gate_max_unsuppressed(
    findings: list[Finding],
    report: ScoreReport,
    gate_config: dict,
    tripped: list[str],
    reasons: list[str],
) -> None:
    caps = gate_config.get("max_unsuppressed", {})
    for sev_str, cap in caps.items():
        sev = Severity.from_string(sev_str)
        count = report.per_severity_count.get(sev, 0)
        if count > cap:
            tripped.append(f"max_unsuppressed.{sev_str}")
            reasons.append(f"{count} unsuppressed {sev.value} finding(s) exceeds cap {cap}")
