"""Scanner protocol + the outcome constructors every adapter builds with.

`Scanner` had grown to 423 lines against a 300-line class limit by holding
four unrelated jobs. Three of them moved out, each to a module that can be
read and reviewed on its own:

- `_resolution.CommandResolution` — which program runs, and whether it can
- `_execution.SubprocessExecution` — running it, and reading its exit code
- `_finding_builder.FindingConstruction` — turning its output into findings

What stays here is what `Scanner` is *for*: the `scan()` contract and the one
constructor per outcome. They are inherited rather than composed because the
suite and fifteen adapters call them as methods on the scanner — `self._exec`,
`self._make_finding`, `BanditScanner._sanitized_env()` — and that surface is
the thing worth keeping stable.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import replace
from pathlib import Path

from secure_code_audit.config import Config, scanner_cfg
from secure_code_audit.findings import Confidence, Finding, Severity
from secure_code_audit.scanner_status import ScannerOutcome, ScanResult
from secure_code_audit.scanners._execution import SubprocessExecution
from secure_code_audit.scanners._finding_builder import FindingConstruction
from secure_code_audit.scanners._resolution import CommandResolution


class Scanner(CommandResolution, SubprocessExecution, FindingConstruction, ABC):
    """Base class for all scanner adapters.

    Subclasses implement `scan()`, returning a `ScanResult` built with the
    outcome constructors below.
    """

    name: str  # canonical id used in config + reports
    #: Wall clock this adapter needs. Scanners that query a remote API are
    #: legitimately slower than ones reading a file tree, and an operator
    #: should not have to discover that from a timeout.
    default_timeout_seconds: int = 600

    #: Whether this adapter tells its tool about `paths.exclude_patterns`.
    #:
    #: The register says `exclude_patterns` *"stops the scan"*, and for a long
    #: time nothing did: every adapter got the bare target root and the
    #: patterns only filtered the findings afterwards. Trivy consequently
    #: walked 342 MB of vendored clones in this repository's own excluded
    #: `calibration/.corpus/`, resolved their Maven dependencies, and was
    #: rate-limited into failing — a *required* scanner, for sixty runs.
    #:
    #: Declared rather than inferred, with `exclusion_note` giving the reason
    #: when it is False, so an adapter cannot quietly ignore the setting; a
    #: lint pairs the two. Finding-level filtering stays authoritative either
    #: way, so this is an optimisation and never the only thing excluding a
    #: path — under-excluding costs time, over-excluding hides real code.
    honours_exclusions: bool = False
    #: Why not, when `honours_exclusions` is False. Required by the lint.
    exclusion_note: str = ""

    def exclusion_args(self, config: Config) -> list[str]:
        """Flags telling this tool which directories not to walk.

        Empty by default: a tool with no way to express it gets nothing, and
        says so in `exclusion_note`.
        """
        return []

    # ----- main entrypoint ------------------------------------------------

    @abstractmethod
    def scan(self, target: Path, config: Config) -> ScanResult:
        """Execute the scanner against target. MUST NOT raise.

        Returns a `ScanResult` stating what happened. Errors become an outcome
        plus a derived control finding, so the audit pipeline never dies on a
        single scanner failing and the orchestrator never has to guess what a
        finding id meant.

        Build the result with `completed()`, `failed()`, `timed_out()`,
        `unavailable()` or `not_applicable()` rather than constructing it
        directly — those keep the outcome and its control finding in step.
        """
        ...

    # ----- results --------------------------------------------------------
    #
    # One constructor per outcome. The control finding is *derived* from the
    # outcome here rather than being the thing an outcome is later inferred
    # from, so an adapter cannot name one and mean the other. See
    # `docs/architecture.md` §2 and `ScanResult`.

    def scope(self, config: ScannerConfig) -> str | None:
        """What this adapter's configuration means it actually covered.

        Declared by the adapter because the orchestrator used to special-case
        scanners by name to supply it — there was nowhere else to put it.
        """
        return None

    def completed(self, findings: Iterable[Finding], *, scope: str | None = None) -> ScanResult:
        """The scanner ran and these are its findings. An empty list is clean."""
        return ScanResult(outcome=ScannerOutcome.COMPLETED, findings=tuple(findings), scope=scope)

    def unavailable(self, target: Path) -> ScanResult:
        finding = self._unavailable_finding(target)
        return ScanResult(
            outcome=ScannerOutcome.UNAVAILABLE, findings=(finding,), reason=finding.message
        )

    def failed(self, target: Path, reason: str, *, findings: Iterable[Finding] = ()) -> ScanResult:
        """The scanner did not cover its ground.

        `findings` carries anything that *was* parsed before the failure. A
        scanner that emitted twenty secrets and three unparseable lines has
        found real defects and still has not scanned the repository, so the
        findings are reported and the outcome stays FAILED. Previously the
        partial findings survived into the report while `classify_execution`
        recorded `finding_count=0` for the same run — the two disagreed
        because neither was the source of truth.
        """
        result = self._control_result(target, ScannerOutcome.FAILED, "tool_error", reason)
        return replace(result, findings=(*findings, *result.findings))

    def timed_out(self, target: Path, reason: str) -> ScanResult:
        return self._control_result(target, ScannerOutcome.TIMED_OUT, "tool_timeout", reason)

    def not_applicable(self, target: Path, reason: str) -> ScanResult:
        """Nothing here for this scanner to read.

        Not a gap: requiring a Terraform scanner of a pure-Python repository
        would make every such repository permanently incomplete. The reason is
        mandatory because silence would read as a pass.
        """
        return self._control_result(target, ScannerOutcome.NOT_APPLICABLE, "not_applicable", reason)

    def _control_result(
        self, target: Path, outcome: ScannerOutcome, suffix: str, reason: str
    ) -> ScanResult:
        finding = self._make_finding(
            rule_id=f"{self.name}.{suffix}",
            message=reason,
            file_path=target,
            line_start=0,
            line_end=None,
            code_snippet=None,
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.HIGH,
        )
        return ScanResult(outcome=outcome, findings=(finding,), reason=reason)

    # ----- shared utility -------------------------------------------------

    def cfg(self, config: Config) -> ScannerConfig:
        """Per-scanner config, with this adapter's own timeout default filled in."""
        resolved = scanner_cfg(config, self.name)
        if resolved.timeout_seconds is None:
            resolved = replace(resolved, timeout_seconds=self.default_timeout_seconds)
        return resolved


# Re-export so the registry import in __init__.py is clean.
from secure_code_audit.config import ScannerConfig  # noqa: E402
