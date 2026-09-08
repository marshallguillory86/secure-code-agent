"""Scanner execution and coverage status.

Findings describe security defects in the target.  Scanner status describes
whether the tools needed to produce those findings actually ran.  Keeping the
two concepts separate prevents a clean finding set from implying complete
coverage.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum

from secure_code_audit.findings import Finding


class ScannerOutcome(str, Enum):
    COMPLETED = "completed"
    # Someone else ran the scanner and handed us the output. We never observed
    # the process, so we cannot assert it succeeded — only that the operator
    # vouched for the file. Distinct from COMPLETED on purpose.
    UNVERIFIED = "unverified"
    UNAVAILABLE = "unavailable"
    NOT_APPLICABLE = "not_applicable"
    TIMED_OUT = "timed_out"
    FAILED = "failed"


#: Outcomes that mean the scanner's ground was covered, verified or not.
COVERING_OUTCOMES = (ScannerOutcome.COMPLETED, ScannerOutcome.UNVERIFIED)


class CoverageStatus(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


@dataclass(frozen=True)
class ScannerExecution:
    name: str
    outcome: ScannerOutcome
    command: tuple[str, ...] = ()
    version: str | None = None
    finding_count: int = 0
    reason: str | None = None
    scope: str | None = None


@dataclass(frozen=True)
class CoverageReport:
    status: CoverageStatus
    required: tuple[str, ...]
    executions: tuple[ScannerExecution, ...]
    failures: tuple[str, ...]
    #: Scanners whose coverage rests on an operator-supplied artifact rather
    #: than a process we watched. Reported everywhere so COMPLETE is never
    #: read as "we verified all of this ourselves".
    unverified: tuple[str, ...] = ()


def classify_execution(
    name: str,
    findings: Iterable[Finding],
    *,
    command: tuple[str, ...] = (),
    version: str | None = None,
    scope: str | None = None,
) -> ScannerExecution:
    """Classify scanner control findings without counting them as coverage."""
    findings = list(findings)
    control = {finding.rule_id: finding for finding in findings}

    checks = (
        (f"{name}.tool_unavailable", ScannerOutcome.UNAVAILABLE),
        (f"{name}.tool_timeout", ScannerOutcome.TIMED_OUT),
        (f"{name}.tool_error", ScannerOutcome.FAILED),
        (f"{name}.parse_error", ScannerOutcome.FAILED),
    )
    for rule_id, outcome in checks:
        if rule_id in control:
            return ScannerExecution(
                name=name,
                outcome=outcome,
                command=command,
                version=version,
                finding_count=0,
                reason=control[rule_id].message,
                scope=scope,
            )

    not_applicable = next(
        (finding for finding in findings if finding.rule_id.startswith(f"{name}.no_")),
        None,
    )
    if not_applicable is not None:
        return ScannerExecution(
            name=name,
            outcome=ScannerOutcome.NOT_APPLICABLE,
            command=command,
            version=version,
            finding_count=0,
            reason=not_applicable.message,
            scope=scope,
        )

    security_findings = sum(
        1 for finding in findings if not finding.rule_id.startswith(f"{name}.tool_")
    )
    return ScannerExecution(
        name=name,
        outcome=ScannerOutcome.COMPLETED,
        command=command,
        version=version,
        finding_count=security_findings,
        scope=scope,
    )


# Worst-first. A scanner can be reported twice — once from a local run and
# once from an imported SARIF — and the degraded result must win so a clean
# import cannot mask a failed local execution.
#
# COMPLETED outranks UNVERIFIED deliberately: if we ran the scanner ourselves
# *and* an import reports it, our own observation is the stronger evidence and
# should not be downgraded by someone else's file.
_OUTCOME_PRECEDENCE: dict[ScannerOutcome, int] = {
    ScannerOutcome.FAILED: 0,
    ScannerOutcome.TIMED_OUT: 1,
    ScannerOutcome.UNAVAILABLE: 2,
    ScannerOutcome.NOT_APPLICABLE: 3,
    ScannerOutcome.COMPLETED: 4,
    ScannerOutcome.UNVERIFIED: 5,
}


def worst_by_name(
    executions: Iterable[ScannerExecution],
) -> dict[str, ScannerExecution]:
    """Collapse duplicate scanner names to their least successful execution."""
    by_name: dict[str, ScannerExecution] = {}
    for execution in executions:
        current = by_name.get(execution.name)
        if (
            current is None
            or _OUTCOME_PRECEDENCE[execution.outcome] < _OUTCOME_PRECEDENCE[current.outcome]
        ):
            by_name[execution.name] = execution
    return by_name


def evaluate_coverage(
    executions: Iterable[ScannerExecution],
    required: Iterable[str],
) -> CoverageReport:
    executions = tuple(executions)
    required = tuple(dict.fromkeys(required))
    by_name = worst_by_name(executions)

    failures: list[str] = []
    for name in required:
        execution = by_name.get(name)
        if execution is None:
            failures.append(f"required scanner {name!r} was not selected")
        elif execution.outcome not in COVERING_OUTCOMES:
            failures.append(
                f"required scanner {name!r} did not complete: {execution.outcome.value}"
            )

    # An unverified import covers the ground, so it does not degrade status to
    # PARTIAL — PARTIAL still means "something did not run". It is named
    # separately instead, so COMPLETE never silently implies we watched every
    # scanner ourselves.
    unverified = tuple(
        execution.name
        for execution in by_name.values()
        if execution.outcome is ScannerOutcome.UNVERIFIED
    )

    if failures:
        status = CoverageStatus.FAILED
    elif any(
        execution.outcome not in (*COVERING_OUTCOMES, ScannerOutcome.NOT_APPLICABLE)
        for execution in executions
    ):
        status = CoverageStatus.PARTIAL
    else:
        status = CoverageStatus.COMPLETE

    return CoverageReport(
        status=status,
        required=required,
        unverified=unverified,
        executions=executions,
        failures=tuple(failures),
    )
