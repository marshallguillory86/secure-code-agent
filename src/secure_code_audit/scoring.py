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


def evidence_reasons(gate_config: dict, coverage: CoverageReport | None) -> tuple[str, ...]:
    """Why the evidence cannot support a verified letter grade, if it cannot.

    The score is a rate over findings, so removing a scanner removes findings
    and the number rises. On one tree, disabling the scanners took it from
    0.00/F to 5.00/A+ — withholding evidence bought the best possible letter.
    A number computed from whatever happened to run cannot be a *grade* unless
    something says what was supposed to run and confirms it did.

    `gates.require_scanners` is that declaration. Without it there is no
    standard to have met, so there is no letter — not a low one, which would
    claim knowledge of poor quality we do not have.
    """
    reasons: list[str] = []
    if not gate_config.get("require_scanners"):
        reasons.append(
            "no gates.require_scanners is declared, so no scanner set was asserted to have run"
        )
    if coverage is None:
        reasons.append("no scanner coverage was evaluated")
    elif coverage.status is not CoverageStatus.COMPLETE:
        reasons.append(f"scanner coverage is {coverage.status.value}")
        reasons.extend(coverage.failures)
    return tuple(reasons)


@dataclass(frozen=True)
class Verdict:
    """What the run is willing to claim, decided once.

    Five renderers used to each decide how to caveat the score, and the SARIF
    one was missed on the first pass. The decision belongs in one place, and
    every output reads it rather than re-deriving it.
    """

    estimate: float
    #: The letter the estimate alone would earn. Not a grade — an arithmetic
    #: consequence, kept so a reader can see what the evidence suggested.
    estimated_letter: str
    verified_grade: str | None
    reasons: tuple[str, ...]

    @property
    def is_verified(self) -> bool:
        return self.verified_grade is not None

    @property
    def evidence_status(self) -> str:
        return "complete" if self.is_verified else "incomplete"

    def headline(self) -> str:
        """One line, used by every renderer that shows a score."""
        if self.is_verified:
            return f"{self.estimate:.2f} ({self.verified_grade})"
        return f"{self.estimate:.2f} — grade withheld ({self.estimated_letter} unverified)"


def verdict(report: ScoreReport, gate_config: dict, coverage: CoverageReport | None) -> Verdict:
    """Decide the letter, or withhold it, once for the whole run."""
    reasons = evidence_reasons(gate_config, coverage)
    return Verdict(
        estimate=report.overall,
        estimated_letter=report.letter,
        verified_grade=None if reasons else report.letter,
        reasons=reasons,
    )


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


#: Categories that are scored wherever they are found, test tree included.
#:
#: A committed credential is a leak whatever directory it sits in, and the
#: corpus supports treating it that way: across six large repositories every
#: single `secrets` finding inside a test tree came from gitleaks — private
#: keys, JWTs, API keys — and not one from Bandit's hardcoded-password
#: heuristics, which land in `code_vulnerabilities` and are the actual noise
#: (7,688 `B101` asserts against 17 real secrets). See docs/calibration.md.
ALWAYS_SCORED_CATEGORIES: frozenset[Category] = frozenset({Category.SECRETS})


def partition_by_tree(
    findings: Iterable[Finding], is_test: Callable[[Finding], bool]
) -> tuple[list[Finding], list[Finding]]:
    """Split findings into (primary, test-tree).

    `is_test` decides on path; this decides on policy. A finding in a category
    that is always scored stays primary however it is classified, which is what
    keeps a real key in a fixture from being filed away as test noise.
    """
    primary: list[Finding] = []
    test: list[Finding] = []
    for finding in findings:
        if is_test(finding) and finding.category not in ALWAYS_SCORED_CATEGORIES:
            test.append(finding)
        else:
            primary.append(finding)
    return primary, test


@dataclass(frozen=True)
class AxisReport:
    """A body of findings reported beside the score rather than inside it.

    Two things live here: the repository's own test tree, and its dependency
    advisories. Both are real findings and both are the wrong thing to average
    into a code-condition grade.

    A hardcoded password in a test double and one in a request handler are not
    the same defect. A CVE in a pinned dev-dependency and an injection flaw you
    wrote are not the same defect either — one is fixed with a version bump and
    the other with a rewrite. `maintainability-agent`'s ADR-007 draws the same
    line when it refuses to average a practice level with a code condition.

    Reported, never discarded: every finding is carried in full, counted, and
    broken down by severity and category. Separating them from the score is the
    opposite of hiding them — before this, seven thousand `assert` statements
    in a test suite outweighed everything a reader needed to see.
    """

    #: What this axis is, in report-facing words: "test tree", "dependencies".
    name: str
    findings: tuple[Finding, ...]
    per_severity_count: dict[Severity, int]
    per_category_count: dict[Category, int]
    #: Lines of code the axis covers, where that means anything. Dependency
    #: advisories are counted against a lockfile, not a line count, so this is
    #: None for them rather than a misleading zero.
    loc: int | None = None

    @property
    def count(self) -> int:
        return len(self.findings)

    @property
    def worst_severity(self) -> Severity | None:
        return max(self.per_severity_count, key=lambda s: s.rank, default=None)

    def headline(self) -> str:
        scope = f" across {self.loc:,} LOC" if self.loc is not None else ""
        if not self.findings:
            return f"{self.name}: nothing found{scope}"
        worst = self.worst_severity
        return (
            f"{self.name}: {self.count} finding(s){scope}"
            + (f", worst {worst.value}" if worst else "")
            + " — reported, not scored"
        )


def summarize_axis(name: str, findings: Iterable[Finding], loc: int | None = None) -> AxisReport:
    """Count an axis without scoring it.

    Not named `test_*` anything: pytest collects any callable whose name begins
    with `test_`, including imported ones, so a public function so named would
    break the suite of every project that imported it.
    """
    findings = tuple(f for f in findings if not f.suppressed)
    per_severity: dict[Severity, int] = {}
    per_category: dict[Category, int] = {}
    for finding in findings:
        per_severity[finding.severity] = per_severity.get(finding.severity, 0) + 1
        per_category[finding.category] = per_category.get(finding.category, 0) + 1
    return AxisReport(
        name=name,
        loc=loc,
        findings=findings,
        per_severity_count=per_severity,
        per_category_count=per_category,
    )


#: Categories reported on their own axis instead of being scored as code
#: condition. Measured at a median `worst_normalized` of 15.36 with them in the
#: score against 7.32 without — the largest single distortion left after the
#: test tree was separated. See docs/calibration.md.
#:
#: They are still *gated*: a critical CVE in a runtime dependency must fail a
#: build. Only the code-condition grade stops absorbing them.
SIDE_AXIS_CATEGORIES: frozenset[Category] = frozenset({Category.DEPENDENCIES})


def split_side_axes(findings: Iterable[Finding]) -> tuple[list[Finding], list[Finding]]:
    """Split findings into (scored, reported-on-their-own-axis)."""
    scored: list[Finding] = []
    side: list[Finding] = []
    for finding in findings:
        (side if finding.category in SIDE_AXIS_CATEGORIES else scored).append(finding)
    return scored, side


#: A category with nothing against it grades here, so nothing below this
#: ceiling means nothing actually drove the grade down.
_PERFECT_GRADE = 5.0


def _worst_category(
    per_category: dict[Category, float],
    per_category_count: dict[Category, int],
) -> Category | None:
    """The category that actually drove the grade, or None if none did.

    This was `min()` over the grade dict, which returns the first key in enum
    order on a tie. Every category grades 5.0 when nothing counts against it,
    so a repository whose findings were all informational reported
    *"worst category: secrets"* while holding zero secrets findings — the first
    member of the enum, named as the problem. Sending an operator to audit a
    clean category is worse than saying nothing.

    Ties below the ceiling are real, and enum order is still the wrong
    tie-break: between two categories at the same grade, the one carrying more
    findings is the more useful thing to look at first.
    """
    if not per_category:
        return None
    lowest = min(per_category.values())
    if lowest >= _PERFECT_GRADE:
        return None
    tied = [category for category, grade in per_category.items() if grade == lowest]
    return max(tied, key=lambda category: per_category_count.get(category, 0))


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

    worst_category = _worst_category(per_category, per_category_count)

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
