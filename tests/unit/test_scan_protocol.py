"""The adapter protocol, enforced structurally.

`docs/architecture.md` §2 named the defect this file exists to prevent:
adapters signalled their outcome by *naming a finding*, and nothing enforced
the convention — "no type, no test, no lint". The twelve adapters were written
at three different times, and the only thing keeping them in step was that
whoever wrote each one had read another one first.

Every audit that identifies a class of bug should ship a lint that blocks the
class from recurring. These are that lint.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

from secure_code_audit import scanners
from secure_code_audit.scanner_status import ScannerOutcome, ScanResult
from secure_code_audit.scanners.base import Scanner

ADAPTER_DIR = Path(inspect.getfile(Scanner)).parent
#: The one module allowed to build a control finding, because it is the one
#: that derives it from the outcome.
CONTROL_FINDING_HOME = "base.py"


def _adapter_sources() -> list[Path]:
    return sorted(
        path
        for path in ADAPTER_DIR.glob("*.py")
        if path.name not in {"__init__.py", CONTROL_FINDING_HOME}
    )


def test_every_registered_scanner_implements_the_result_protocol():
    """A list-returning adapter must not be constructible.

    `scan` is abstract, so an adapter that still defines only `run` fails at
    instantiation rather than silently handing the orchestrator the wrong type.
    """
    assert scanners.SCANNERS, "the registry is empty; this test would pass vacuously"
    for name, cls in scanners.SCANNERS.items():
        instance = cls()  # raises TypeError if `scan` is unimplemented
        assert callable(instance.scan), name
        annotation = inspect.signature(cls.scan).return_annotation
        assert annotation in (ScanResult, "ScanResult"), (
            f"{name}.scan is annotated {annotation!r}; the orchestrator reads "
            f"`.outcome` and `.findings` off the return value"
        )


@pytest.mark.parametrize("source", _adapter_sources(), ids=lambda p: p.name)
def test_no_adapter_hand_builds_a_control_finding(source: Path):
    """Control findings are derived from the outcome, in exactly one place.

    An adapter that writes `rule_id=f"{self.name}.tool_error"` itself has
    re-created the two-sources-of-truth problem: the string says one thing and
    the outcome says another, and only one of them reaches coverage. Use
    `self.failed(...)`, `self.timed_out(...)`, `self.not_applicable(...)` or
    `self.unavailable(...)`, which set both together.
    """
    offenders: list[str] = []
    for node in ast.walk(ast.parse(source.read_text(encoding="utf-8"))):
        if not isinstance(node, ast.JoinedStr):
            continue
        # An f-string containing `self.name` followed by a control suffix.
        literal = "".join(part.value for part in node.values if isinstance(part, ast.Constant))
        if literal.startswith(".") and any(
            literal.startswith(f".{suffix}")
            for suffix in ("tool_error", "tool_timeout", "tool_unavailable", "parse_error", "no_")
        ):
            offenders.append(f"line {node.lineno}: ...{literal}")

    assert offenders == [], (
        f"{source.name} builds a control finding by hand: {offenders}. "
        f"Outcome and control finding must be set together — see "
        f"Scanner._control_result in {CONTROL_FINDING_HOME}."
    )


def test_a_non_completed_result_cannot_be_silent():
    """An outcome that is not COMPLETED has to say why.

    A FAILED scanner with no reason reaches a report as a blank cell, which is
    indistinguishable from a scanner nobody asked about. The type refuses it.
    """
    for outcome in ScannerOutcome:
        if outcome is ScannerOutcome.COMPLETED:
            assert ScanResult(outcome=outcome).findings == ()
            continue
        with pytest.raises(ValueError, match="requires a reason"):
            ScanResult(outcome=outcome)
        assert ScanResult(outcome=outcome, reason="stated").reason == "stated"


def test_a_failed_run_keeps_its_partial_findings_but_not_its_count():
    """Both halves of the partial-failure case, which used to disagree.

    A scanner that parsed twenty secrets and then hit three unreadable lines
    has found real defects *and* has not scanned the repository. The findings
    survive into the report; the execution records zero, because a count taken
    from an incomplete run reads as progress.
    """
    from secure_code_audit.scanner_status import execution_from_result

    completed = ScanResult(outcome=ScannerOutcome.COMPLETED, findings=(object(),) * 3)
    failed = ScanResult(
        outcome=ScannerOutcome.FAILED, findings=(object(),) * 3, reason="3 bad lines"
    )

    assert execution_from_result("x", completed).finding_count == 3
    assert execution_from_result("x", failed).finding_count == 0
    assert len(failed.findings) == 3


def test_scope_is_declared_by_the_adapter_not_by_a_name_check():
    """The orchestrator no longer special-cases scanners by name.

    `cli.py` carried `if name != "pip_audit": return None` because there was
    nowhere on an adapter to declare what it covered. Every adapter now answers
    for itself, defaulting to None.
    """
    from secure_code_audit.config import ScannerConfig

    config = ScannerConfig()
    scoped = {name for name, cls in scanners.SCANNERS.items() if cls().scope(config) is not None}

    # pip_audit's answer depends on what it was pointed at; semgrep's depends
    # on which ruleset ran. Both are reproducibility claims, not decoration.
    assert scoped == {"pip_audit"} or scoped == {"pip_audit", "semgrep"}, scoped
