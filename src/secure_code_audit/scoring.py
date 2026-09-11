"""Scoring + gate evaluation.

Implements the model documented in docs/scoring.md:
  · finding_score = severity × confidence × category × top25_bonus
  · category_subtotal = Σ finding_score per category
  · category_normalized = subtotal / (LOC / 1000)
  · category_grade = clamp(5.0 - (normalized × 1.5), 0, 5)
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

#: Which scoring model produced a number, for consumers that keep a trend.
#:
#: `maintainability-agent` stores this tool's `condition` in its scan history
#: and has to know when two readings are comparable. A delegated pillar can
#: change its scoring model **without changing its schema** — same shape, same
#: fields, a different number for the same repository — which is exactly what
#: D16 and D17 did. MA previously keyed on our release version, which is
#: correct but far too broad: it opened a new series on every release,
#: including ones that changed no scoring, and a signal that fires constantly
#: teaches people to ignore it.
#:
#: **Bump this when a repository's condition could differ for a reason that is
#: not the repository.** Concretely: the normalizer, the grade slope, any
#: weight table, the letter bands, the rank discount, `COUNT_LIKE_CATEGORIES`,
#: the scanner floor, or the built-in rule profile (D10).
#:
#: **Do not bump for** documentation, adapters, CLI flags, output formats,
#: performance, or a parser fix that does not change which findings are
#: produced.
#:
#: A new *rule* does bump it. That was the arguable case and it resolves
#: against intuition: a repository containing `yaml.unsafe_load` scores lower
#: the day that rule ships, with no change to the repository. Adding findings
#: *is* rescoring, because the score is a function of the finding set, and a
#: user must not read "we can see more now" as "your code got worse".
#:
#: **1 is reserved and is never emitted.** It denotes every release before
#: this field existed, and those releases do not share one model — the
#: corroboration merge, the rank discount and D16 all moved the numbers. A v1
#: document simply omits the field and MA keys those on the release version,
#: which fragments them correctly. Nothing may back-fill a 1.
#:
#: `tests/integration/test_scoring_drift.py` holds this honest: it digests the
#: weights, the bands and the output of the real `score()` over a fixed
#: matrix, so changing a constant *or* a formula without bumping this fails.
SCORING_MODEL = 2


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

    #: None when nothing could be measured. Not zero: a run with no
    #: measurable category has no estimate to report, and a 0.00 would read as
    #: "we looked and it was terrible".
    estimate: float | None
    #: The letter the estimate alone would earn. Not a grade — an arithmetic
    #: consequence, kept so a reader can see what the evidence suggested.
    estimated_letter: str | None
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
        if self.estimate is None:
            return "no score — nothing measurable was scanned"
        if self.is_verified:
            return f"{self.estimate:.2f} ({self.verified_grade})"
        return f"{self.estimate:.2f} — grade withheld ({self.estimated_letter} unverified)"


def verdict(report: ScoreReport, gate_config: dict, coverage: CoverageReport | None) -> Verdict:
    """Decide the letter, or withhold it, once for the whole run."""
    reasons = list(evidence_reasons(gate_config, coverage))
    if report.overall is None:
        # Nothing measurable ran. There is no estimate to qualify, so the
        # reason is stated rather than a letter being caveated — a caveated
        # letter still shows a letter.
        reasons.append("no category could be measured by the scanners that ran")
    return Verdict(
        estimate=report.overall,
        estimated_letter=report.letter,
        verified_grade=None if reasons else report.letter,
        reasons=tuple(reasons),
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
    """Sum a category's findings, saturating each rule's repeats.

    A straight sum measures how many times a pattern matched, and that
    tracks codebase size times how talkative the scanner is — not how much
    risk is in the code. The normalizer was meant to cancel the size half.
    Nothing cancelled the other half, and the corpus said so plainly: the
    worst-first ordering read Python → JavaScript → Go/Ruby → Java, which is
    the order of Bandit's verbosity, and Django, FastAPI, httpx and Flask all
    graded F.

    Inspecting what held them there settled it. Django's `B105 hardcoded
    password` hits were `EMAIL_HOST_PASSWORD = ""` and `SECRET_KEY = ""` —
    empty defaults. Its `B608 SQL injection` hits included
    `raise ImproperlyConfigured('Cannot determine PostGIS version for …')`,
    an error message, and `cursor.execute("SELECT %s, … FROM %s")`, which is
    parameterised. Its 56 `mark_safe` hits are the framework implementing
    its own escaping. Each one is a real pattern match and almost none is a
    defect, so summing them graded Django on how much Django there is.

    So repeats of one rule saturate. One rule firing n times is one fact
    about the codebase observed n times, not n independent defects. Distinct
    rules still add in full, because they are independent evidence.

    The saturation is a **rank discount**: sort a rule's hits worst-first and
    give the k-th one `weight / sqrt(k)`. The total grows as roughly
    `2 * sqrt(n)` — saturating — while every additional finding still adds
    something.

    That last property is P3, and the obvious formulation breaks it. Scoring
    a rule as `mean(weight) * sqrt(n)` is also saturating, and under it one
    CRITICAL plus nine LOW hits of one rule scored 6.88 against 15.0 for the
    CRITICAL alone: nine extra findings *improved* the grade, so withholding
    evidence would have raised it. A rank discount cannot do that — the
    worst hit always lands at k=1 with its full weight, and every later one
    adds a non-negative amount.
    """
    by_rule: dict[str, list[float]] = {}
    for finding in findings:
        if finding.category is not category or finding.suppressed:
            continue
        by_rule.setdefault(finding.rule_id, []).append(finding_score(finding))
    return sum(
        sum(score / math.sqrt(rank) for rank, score in enumerate(sorted(scores, reverse=True), 1))
        for scores in by_rule.values()
    )


#: Categories where a finding is a count rather than a rate.
#:
#: One committed credential is one committed credential regardless of how
#: much code surrounds it. Everything else here — injection sinks, weak
#: crypto calls, unsafe deserialization — genuinely does scale with how much
#: code there is, and comparing two repositories on those means comparing
#: rates. See `normalize` for the measurement that settled which is which.
COUNT_LIKE_CATEGORIES: frozenset[str] = frozenset({"secrets"})


def _category_name(category: Category | str) -> str:
    return category.value if isinstance(category, Category) else str(category)


def normalize(subtotal: float, loc_scanned: int, category: Category | str | None = None) -> float:
    """Weighted findings per thousand lines of scanned code — a density.

    This was `sqrt(LOC/1000)` and that under-corrected for size, so the
    ranking followed how *big* a repository is rather than how much is wrong
    with it. Measured across the examined corpus:

        repo      LOC        weighted findings/kLOC   sqrt-normalized
        django    144,473    1.51                     18.18  <- ranked worst
        flask       7,841    3.35                      9.38
        fastapi    23,764    1.60                      7.81

    Flask carries **2.2x Django's finding density** and normalised at half
    the value. Django sat fifth by density and first by penalty. Spearman
    correlation of grade against size was -0.37 while correlation of density
    against size was +0.12: the number was tracking the wrong variable.

    Straight density fixes the ordering: re-measured over the same corpus
    after the change, Spearman(LOC, grade) is +0.02, and the worst-ranked
    repository is the densest one rather than the largest one. The slope
    moves with it — see `category_grade` — because the two only make sense
    together.

    **`secrets` is not a density, and D17 is why.** Adding
    vulnerable-by-design anchors to the corpus exposed the failure directly:
    OWASP Juice Shop carries four hardcoded API keys and three private keys
    and graded **B+**, because 115,340 lines of surrounding code divided
    seven committed credentials down to nothing. Meanwhile Flask, with no
    secrets at all, graded F. A committed private key is one committed
    private key whether the repository is a thousand lines or a million; it
    is a count, not a rate, and dividing it by size is how a training
    application built to be insecure outscored a well-run library.

    So `secrets` normalizes by `sqrt(LOC/1000)` instead. Not by nothing: a
    larger codebase genuinely does carry more configuration surface, and an
    absolute count made Django fail on two low-confidence hits. Measured over
    the fourteen examined repositories, against whether a repository is
    maintained or written to be vulnerable:

        variant                       AUC    separation   Spearman(LOC, grade)
        linear everywhere (D16)       0.80      -3.76            +0.14
        sqrt everywhere (pre-D16)     0.91      -0.58            -0.32
        linear; secrets absolute      0.90      +0.00            -0.24
        linear; secrets sqrt          1.00      +0.65            -0.01   <-

    AUC is the probability that a maintained repository outscores a
    vulnerable-by-design one. Negative separation means the populations
    overlap and *no* band table can tell them apart — which is what blocked
    D5's band edges for as long as the corpus had no bad end in it.
    """
    if loc_scanned <= 0:
        return subtotal
    per_kloc = max(loc_scanned, 1) / 1000
    if category is not None and _category_name(category) in COUNT_LIKE_CATEGORIES:
        return subtotal / math.sqrt(per_kloc)
    return subtotal / per_kloc


#: Grade points lost per normalized weighted finding.
#:
#: The slope only rescales — it cannot reorder anything — so it is chosen
#: against two things the ordering does not fix: where the median of
#: well-maintained code lands, and how much of the corpus clamps at 0.0 and
#: loses its tail.
#:
#: 1.3 is the largest slope that keeps the maintained-corpus median inside the
#: B band [3.00, 3.50) *and* keeps the two populations from touching. Measured
#: across the range, holding the D17 normalizer fixed:
#:
#:     slope   median (maintained)   AUC   separation   clamped at 0
#:      1.2          3.53 (B+)       1.00     +0.98          4
#:      1.3          3.41 (B)        1.00     +0.65          4   <- adopted
#:      1.4          3.28 (B)        1.00     +0.31          4
#:      1.5          3.16 (B)        0.95     +0.00          5
#:
#: At 1.5 a maintained repository joins the four vulnerable-by-design ones at
#: the clamp, the populations touch, and AUC falls. 1.3 has the widest margin
#: of the slopes that land the median in B.
#:
#: The cost, stated: a large repository with a handful of serious findings
#: still scores better than a small noisy one. A 135,841-line control carrying
#: SQL injection, `shell=True`, `pickle.loads`, MD5 and `eval` grades in the
#: A band. What protects that repository is the default `fail_on_new` gate,
#: which fails it outright, and the work order, which puts all seven findings
#: in §FIX. A grade is for comparing and for trend; it was never the thing
#: that catches a vulnerability. See D16 and D17.
GRADE_SLOPE = 1.3


def category_grade(normalized: float) -> float:
    return max(0.0, min(5.0, 5.0 - (normalized * GRADE_SLOPE)))


# --- overall score ---------------------------------------------------------


@dataclass(frozen=True)
class ScoreReport:
    """Per-category + overall score breakdown. Renderers consume this directly."""

    #: category → 0.0-5.0 grade, or **None where nothing could measure it**.
    #: Never a default. A category graded 5.0 because no scanner in the run can
    #: read that language is the absence-as-value defect: the number says
    #: "clean" and means "nobody looked". `architecture.md` §5.
    per_category: dict[Category, float | None]
    per_category_count: dict[Category, int]  # category → unsuppressed finding count
    per_severity_count: dict[Severity, int]  # severity → unsuppressed finding count
    #: The worst *measured* category, or None when nothing was measured at all.
    overall: float | None
    letter: str | None  # A+, A, A-, B+, ... or None alongside a None overall
    worst_category: Category | None  # which category drove the grade
    loc_scanned: int  # for the report header

    @property
    def is_measured(self) -> bool:
        return self.overall is not None

    def as_table(self) -> list[tuple[str, str, float | None, int]]:
        """[(category_name, grade_letter, grade_score, finding_count), ...]
        sorted worst → best, with unmeasured categories last.

        An unmeasured category reports "—" rather than a letter. Sorting it to
        the end is deliberate: it is not the worst thing found, it is a thing
        nobody looked at, and putting it at the top of a worst-first table
        would read as an accusation.
        """
        rows = []
        for cat in Category:
            grade = self.per_category.get(cat)
            count = self.per_category_count.get(cat, 0)
            rows.append(
                (cat.value, letter_grade(grade) if grade is not None else "—", grade, count)
            )
        rows.sort(key=lambda r: (r[2] is None, r[2] if r[2] is not None else 0.0))
        return rows


def partition_by_path(
    findings: Iterable[Finding], classify: Callable[[Finding], str]
) -> tuple[list[Finding], dict[str, list[Finding]]]:
    """Split findings by which tree they came from.

    `classify` returns "primary" for the project's own source, or the name of
    a side axis — "test tree", "documentation". Nothing is dropped: every
    finding lands somewhere and every axis is reported.

    Secrets are no longer exempted back onto the primary axis. They follow
    their path like everything else and are escalated at the *gate* instead —
    see `gated_findings`. A test certificate is not a code-condition defect,
    and a leaked key still fails the build.
    """
    primary: list[Finding] = []
    axes: dict[str, list[Finding]] = {}
    for finding in findings:
        name = classify(finding)
        if name == "primary":
            primary.append(finding)
        else:
            axes.setdefault(name, []).append(finding)
    return primary, axes


#: Categories that still **fail a build** from a side axis, even though they
#: do not grade code condition.
#:
#: The exemption used to be the other way round: secrets were *scored*
#: wherever they lived, on the reasoning that every test-tree secret in the
#: corpus came from gitleaks rather than Bandit's heuristics. That was true and
#: insufficient. Measured again with paths: `requests` had four criticals in
#: `tests/certs/*.key` — certificates its own suite generates — and FastAPI had
#: JWTs in four translations of one tutorial. gitleaks being a real secret
#: scanner does not make a test fixture a real secret.
#:
#: Nothing static separates a live credential from a test cert, which is why
#: the remedy is not to score them and not to ignore them. They are reported in
#: full and they still trip `fail_on_category`, so a genuinely leaked key fails
#: the build from anywhere in the tree. Only the code-condition grade stops
#: absorbing them.
GATED_FROM_ANY_AXIS: frozenset[Category] = frozenset({Category.SECRETS})


def gated_findings(
    scored: Iterable[Finding], side_axes: Iterable[Iterable[Finding]], gate_config: dict
) -> list[Finding]:
    """Everything the gate should see: the scored set plus side-axis findings
    in categories the operator named.

    Not simply "everything". A test tree holds hundreds of HIGH findings that
    are deliberately vulnerable fixtures, and feeding those to
    `fail_on_severity` would fail every build in the corpus. A secret is
    different: `fail_on_category: ["secrets"]` is the operator saying *these
    matter wherever they are*, and honouring that is what keeps moving secrets
    off the score from becoming a way to hide one.
    """
    named = {
        Category(value)
        for value in (gate_config.get("fail_on_category") or [])
        if value in {c.value for c in Category}
    }
    escalate = named & GATED_FROM_ANY_AXIS
    out = list(scored)
    if escalate:
        for axis in side_axes:
            out.extend(f for f in axis if f.category in escalate)
    return out


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
    #: Every finding on this axis, **suppressed ones included**. This is the
    #: axis's membership, and the renderer reads it to tag each finding with
    #: the axis it came from.
    #:
    #: Suppressed findings used to be filtered out here. The counts were right
    #: and the membership was wrong, so a suppressed test-tree finding matched
    #: no axis, fell through to the "primary" default, and was published as
    #: `axis: primary, scored: true`. Suppressing a finding is not supposed to
    #: move it into the scored set — the tool's own self-audit did exactly
    #: that after one gitleaks false positive was suppressed.
    #:
    #: The counts below still exclude suppressed findings: an operator who
    #: accepted a finding should not keep reading it in the totals.
    findings: tuple[Finding, ...]
    per_severity_count: dict[Severity, int]
    per_category_count: dict[Category, int]
    #: Lines of code the axis covers, where that means anything. Dependency
    #: advisories are counted against a lockfile, not a line count, so this is
    #: None for them rather than a misleading zero.
    loc: int | None = None

    @property
    def count(self) -> int:
        """Live findings on this axis. Suppressed ones are members, not counts."""
        return sum(1 for f in self.findings if not f.suppressed)

    @property
    def suppressed_count(self) -> int:
        return sum(1 for f in self.findings if f.suppressed)

    @property
    def worst_severity(self) -> Severity | None:
        return max(self.per_severity_count, key=lambda s: s.rank, default=None)

    def headline(self) -> str:
        scope = f" across {self.loc:,} LOC" if self.loc is not None else ""
        if not self.count:
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
    # Membership keeps everything; the counts keep only what is still live.
    # Dropping suppressed findings from `findings` broke the renderer's axis
    # lookup and republished them as scored primary-tree findings.
    findings = tuple(findings)
    per_severity: dict[Severity, int] = {}
    per_category: dict[Category, int] = {}
    for finding in findings:
        if finding.suppressed:
            continue
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


def score(
    findings: Iterable[Finding],
    loc_scanned: int,
    measurable: Iterable[Category] | None = None,
) -> ScoreReport:
    """Grade the findings. Categories nothing could measure grade None.

    `measurable` is the set of categories some scanner in this run could
    actually have reported on. Passing None means "assume everything was
    measurable", which keeps the arithmetic tests honest and is wrong for a
    real audit — the orchestrator derives the real set from coverage.

    It is computed by the caller rather than here on purpose. Working it out
    means knowing which scanners ran and what each one reads, and a rubric
    that can reach into the scanner layer is a rubric that can grow a special
    case for a particular repository. MA keeps the same boundary and enforces
    it with `test_scoring_never_imports_scanners_or_assembly`.
    """
    findings = list(findings)
    measured = set(Category) if measurable is None else set(measurable)
    per_category: dict[Category, float | None] = {}
    per_category_count: dict[Category, int] = {}
    per_severity_count: dict[Severity, int] = dict.fromkeys(Severity, 0)

    for cat in Category:
        count = sum(1 for f in findings if f.category == cat and not f.suppressed)
        per_category_count[cat] = count
        # A finding *is* evidence the category was measurable, whatever the
        # scanner inventory says — otherwise a tool reporting outside its
        # declared domain would have its findings graded as unmeasured.
        if cat not in measured and count == 0:
            per_category[cat] = None
            continue
        subtotal = category_subtotal(findings, cat)
        per_category[cat] = category_grade(normalize(subtotal, loc_scanned, cat))

    for f in findings:
        if not f.suppressed:
            per_severity_count[f.severity] += 1

    graded = {cat: grade for cat, grade in per_category.items() if grade is not None}
    worst_category = _worst_category(graded, per_category_count)
    # None, not 5.0. A run where nothing could be measured has no grade, and
    # this is the defect architecture.md §5 named: the score's null state was
    # "perfect", so a repository nobody scanned reported A+.
    overall = min(graded.values()) if graded else None
    return ScoreReport(
        per_category=per_category,
        per_category_count=per_category_count,
        per_severity_count=per_severity_count,
        overall=overall,
        letter=letter_grade(overall) if overall is not None else None,
        worst_category=worst_category,
        loc_scanned=loc_scanned,
    )


# --- gate evaluation -------------------------------------------------------


@dataclass(frozen=True)
class GateResult:
    passed: bool
    reasons: tuple[str, ...]  # human-readable trip reasons
    tripped: tuple[str, ...] = field(default_factory=tuple)
    #: Gates that could actually have failed this run. Empty means no
    #: policy was configured, which is **not** the same as passing one.
    #:
    #: `passed` stays True in that case — no gate tripped, which is
    #: accurate — but reporting it as PASS is a claim nothing checked. A
    #: 200,000-line repository carrying SQL injection, `shell=True`,
    #: `pickle.loads` and `eval` printed "gate PASS" out of the box, with
    #: no configuration, because an absent gate cannot trip. The work
    #: order listed all seven findings correctly at the same time.
    #:
    #: `_require_configured_gates` already refuses `--fail-on-gate` in this
    #: situation, calling it "a green build with no security floor". This
    #: is the same fact, carried far enough to reach the summary line a
    #: person actually reads.
    configured: tuple[str, ...] = field(default_factory=tuple)

    @property
    def enforced(self) -> bool:
        """Did any gate actually stand between these findings and a pass?"""
        return bool(self.configured)


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
        configured=active_gates(gate_config),
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
        # What "new" means depends on whether there is anything to be new
        # *against*. Saying "since baseline" when no baseline exists claims
        # these findings appeared after one, which is the opposite of the
        # truth on a first run.
        baseline_state = gate_config.get("_baseline_state")
        if baseline_state == "absent":
            reasons.append(
                f"{len(new_findings)} finding(s), and no baseline exists yet — on a first "
                f"run everything is new because there is nothing to compare against. "
                f"Work the order, then re-run with --bump-baseline to accept what is "
                f"left and gate on regressions from there."
            )
        elif baseline_state == "unreadable":
            reasons.append(
                f"{len(new_findings)} finding(s) read as new because the baseline file "
                f"could not be parsed. Fix or delete it — a broken baseline silently "
                f"turns an established repository back into a first run."
            )
        else:
            reasons.append(f"{len(new_findings)} new finding(s) since baseline")


def _gate_min_score(
    findings: list[Finding],
    report: ScoreReport,
    gate_config: dict,
    tripped: list[str],
    reasons: list[str],
) -> None:
    min_score = gate_config.get("min_score")
    if min_score is not None and report.overall is None:
        # A minimum cannot be met by a run that measured nothing, and it
        # certainly is not met *because* nothing was measured. This is the
        # gate half of P3: withholding evidence must not buy a pass.
        tripped.append("min_score")
        reasons.append(
            f"a minimum score of {min_score} is required, and nothing measurable was scanned"
        )
        return
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
