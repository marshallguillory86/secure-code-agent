"""`security-pillar.json` — the artifact `maintainability-agent` ingests (D3).

MA's [ADR 007](https://github.com/marshallguillory86/maintainability-agent/blob/main/docs/adr-007-pillars-and-practice.md)
declares Security a `DELEGATED` pillar naming this tool, and reports it as
`NotApplicable` so a reader never mistakes silence for safety. This module is
the other half: the thing that makes that entry unnecessary.

**Changing this document's shape is a two-repository release, in order.**

MA refuses an unknown `schema` or `schema_version` outright and reports no
delegated pillar rather than a partial one — deliberately, because "the schema
string is the producer's promise about the shape, and guessing past it is how
a consumer starts reporting fields that mean something different." That is the
safe failure and a *silent* one.

So a v2 ships in this sequence and no other:

1. specify the v2 shape and send it to MA;
2. **MA lands its reader first** and accepts v1 and v2;
3. only then does this tool emit v2.

Emitting v2 before MA accepts it leaves the pillar unmeasured for the entire
window between the two releases, with nothing on either side reporting why.
MA will not pre-accept an unspecified v2, which is correct for the same reason
this rule exists. Agreed with the MA maintainer 2026-09-11; see D18 and MA's
D155.

**`producer.version` is load-bearing and is not ours alone.** MA's D155 keys
trend comparability on it, because a delegated pillar can change its scoring
model without changing its schema — which is exactly what D16 and D17 did.
A new MA series opens on *every* release of this tool, including releases that
change no scoring; that over-breaking is agreed and documented on MA's side.
It means a wrong version here silently splices two scoring models into one
trend, so `tests/unit/test_pillar_contract.py` pins the field to
`__version__` rather than merely to `str`.

**Everything structural here is MA's and is reused deliberately.** The scope
vocabulary, the two-axis split, the posture matrix and its thresholds all come
from `_pillars.py`. Two tools reporting "level 3" or "healthy" about the same
repository must mean the same thing by it, or the joined view is worse than
either tool alone.

Three properties carry across, and each exists because its absence caused a
real defect:

**Two values that are never averaged.** Practice level says whether anything
prevents the next vulnerability; condition says what the scanners found. A
clean scan with no enforcement is `unverified`, not healthy — that cell is
where MA's hello-world A+ came from, and where a never-scanned repository would
land here.

**Condition is None when nothing was measured**, never zero and never a
default. This tool's own failure mode is the sharper one: withholding scanners
*raises* a finding-rate score, so an unscanned repository would otherwise
report perfect. Coverage decides whether a number is admissible at all.

**Nothing in this module combines the two axes.** `test_the_pillar_never_averages_its_two_axes`
parses it and refuses a function that would, the same guard MA keeps over
`_pillars.py`.
"""

from __future__ import annotations

import datetime
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from secure_code_audit import __version__
from secure_code_audit.practice import PracticeLevel
from secure_code_audit.scanner_status import CoverageReport, CoverageStatus
from secure_code_audit.scoring import AxisReport, ScoreReport, Verdict

#: MA's matrix thresholds, imported by value because the two tools must agree
#: on where the cells fall. `_pillars.py` holds the originals.
HIGH_PRACTICE = 3
GOOD_CONDITION = 3.5

#: This tool's position on the pillar it owns. MA declares the same pillar
#: `delegated`; the pair is what makes the reporting complete.
SCOPE = "owned"

SCOPE_REASON = (
    "secure-code-agent owns the security pillar: it runs the scanner floor, "
    "reports coverage as a separate axis, and withholds a grade when the "
    "evidence cannot support one"
)


def posture(level: int, condition: float | None) -> str:
    """Which cell of the practice/condition matrix this repository sits in.

    MA's `_pillars.posture`, unchanged. `condition is None` means nothing was
    measured, so there is nothing to be reassured by: the practice axis answers
    alone and can only reach `unverified`, never `healthy`, which would be a
    maturity level vouching for code nobody looked at.
    """
    enforced = level >= HIGH_PRACTICE
    if condition is None:
        return "unverified"
    if condition >= GOOD_CONDITION:
        return "healthy" if enforced else "unverified"
    return "managed debt" if enforced else "unmanaged debt"


@dataclass(frozen=True)
class SecurityPillar:
    """The security pillar as one document, with both axes side by side."""

    practice: PracticeLevel
    condition: float | None
    condition_letter: str | None
    verified_grade: str | None
    evidence_status: str
    evidence_reasons: tuple[str, ...]
    coverage_status: str
    scanners_run: tuple[str, ...]
    scanners_missing: tuple[str, ...]
    findings_by_severity: dict[str, int]
    side_axes: dict[str, dict[str, Any]]
    loc_scanned: int

    @property
    def posture(self) -> str:
        return posture(self.practice.level, self.condition)


def build(
    score: ScoreReport,
    verdict: Verdict,
    coverage: CoverageReport | None,
    practice: PracticeLevel,
    axes: tuple[AxisReport, ...] = (),
) -> SecurityPillar:
    """Assemble the pillar. Condition is admitted only when evidence supports it.

    The gate on `condition` is the whole safety property. This tool's score is a
    rate over findings, so removing scanners removes findings and the number
    goes *up* — on one tree, disabling them took it from 0.00/F to 5.00/A+.
    A number produced that way is not a condition reading, and handing it to MA
    would launder it into a pillar report that looks measured.
    """
    measured = coverage is not None and coverage.status is CoverageStatus.COMPLETE
    condition = score.overall if measured else None
    return SecurityPillar(
        practice=practice,
        condition=condition,
        condition_letter=score.letter if measured else None,
        verified_grade=verdict.verified_grade,
        evidence_status=verdict.evidence_status,
        evidence_reasons=verdict.reasons,
        coverage_status=coverage.status.value if coverage else "unknown",
        scanners_run=tuple(
            execution.name
            for execution in (coverage.executions if coverage else ())
            if execution.outcome.value in ("completed", "unverified")
        ),
        scanners_missing=tuple(
            execution.name
            for execution in (coverage.executions if coverage else ())
            if execution.outcome.value not in ("completed", "unverified", "not_applicable")
        ),
        findings_by_severity={
            severity.value: count for severity, count in score.per_severity_count.items() if count
        },
        side_axes={
            axis.name.replace(" ", "_"): {
                "count": axis.count,
                "loc": axis.loc,
                "worst_severity": axis.worst_severity.value if axis.worst_severity else None,
            }
            for axis in axes
        },
        loc_scanned=score.loc_scanned,
    )


def to_dict(pillar: SecurityPillar) -> dict[str, Any]:
    """The document MA reads. Both axes present, their mean absent."""
    return {
        "schema": "secure-code-agent/security-pillar",
        "schema_version": 1,
        "producer": {"tool": "secure-code-agent", "version": __version__},
        "generated": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "pillar": "security",
        "scope": SCOPE,
        "reason": SCOPE_REASON,
        # ADR 007 §2: two independent values, never averaged. A consumer reads
        # either one; nothing in this document offers their mean.
        "practice": pillar.practice.as_dict(),
        "condition": pillar.condition,
        "condition_letter": pillar.condition_letter,
        "posture": pillar.posture,
        # ADR 001: the estimate, the evidence, and the grade are three fields.
        # `verified_grade` is null whenever the evidence cannot support one.
        "verified_grade": pillar.verified_grade,
        "evidence_status": pillar.evidence_status,
        "evidence_reasons": list(pillar.evidence_reasons),
        "coverage": {
            "status": pillar.coverage_status,
            "scanners_run": list(pillar.scanners_run),
            "scanners_missing": list(pillar.scanners_missing),
        },
        "findings_by_severity": pillar.findings_by_severity,
        "reported_not_scored": pillar.side_axes,
        "loc_scanned": pillar.loc_scanned,
        "notes": {
            "condition_null": (
                "condition is null when scanner coverage is incomplete. This "
                "tool's score is a rate over findings, so withholding scanners "
                "raises it; a number produced that way is not a reading."
            ),
            "never_average": (
                "practice and condition answer different questions and must "
                "not be combined into one number (MA ADR 007 §2)."
            ),
        },
    }


def write(pillar: SecurityPillar, path: Path) -> None:
    path.write_text(json.dumps(to_dict(pillar), indent=2) + "\n", encoding="utf-8")
