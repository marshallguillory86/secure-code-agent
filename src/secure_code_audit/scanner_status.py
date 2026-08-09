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
    UNAVAILABLE = "unavailable"
    NOT_APPLICABLE = "not_applicable"
    TIMED_OUT = "timed_out"
    FAILED = "failed"


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


@dataclass(frozen=True)
class CoverageReport:
    status: CoverageStatus
    required: tuple[str, ...]
    executions: tuple[ScannerExecution, ...]
    failures: tuple[str, ...]


def classify_execution(
    name: str,
    findings: Iterable[Finding],
    *,
    command: tuple[str, ...] = (),
    version: str | None = None,
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
    )


def evaluate_coverage(
    executions: Iterable[ScannerExecution],
    required: Iterable[str],
) -> CoverageReport:
    executions = tuple(executions)
    required = tuple(dict.fromkeys(required))
    by_name = {execution.name: execution for execution in executions}

    failures: list[str] = []
    for name in required:
        execution = by_name.get(name)
        if execution is None:
            failures.append(f"required scanner {name!r} was not selected")
        elif execution.outcome is not ScannerOutcome.COMPLETED:
            failures.append(
                f"required scanner {name!r} did not complete: {execution.outcome.value}"
            )

    if failures:
        status = CoverageStatus.FAILED
    elif any(
        execution.outcome not in (ScannerOutcome.COMPLETED, ScannerOutcome.NOT_APPLICABLE)
        for execution in executions
    ):
        status = CoverageStatus.PARTIAL
    else:
        status = CoverageStatus.COMPLETE

    return CoverageReport(
        status=status,
        required=required,
        executions=executions,
        failures=tuple(failures),
    )
