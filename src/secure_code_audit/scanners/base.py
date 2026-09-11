"""Scanner protocol + subprocess helpers."""

from __future__ import annotations

import importlib.util
import os
import re
import shutil
import subprocess
import sys
from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import replace
from pathlib import Path

from secure_code_audit.config import Config, is_within, scanner_cfg, target_executables_allowed
from secure_code_audit.findings import Category, Confidence, Finding, Severity
from secure_code_audit.scanner_status import ScannerOutcome, ScanResult
from secure_code_audit.standards import StandardsEntry, is_top25, lookup, owasp_for_cwe

#: CSI escape sequences. Tools colourise `--version` and we store the result.
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


class Scanner(ABC):
    """Base class for all scanner adapters.

    Subclasses implement `scan()`, returning a `ScanResult` built with the
    outcome constructors below.
    """

    name: str  # canonical id used in config + reports
    binary: str  # name of the executable on PATH
    version_flag: str = "--version"
    python_module: str | None = None
    default_category: Category = Category.CODE_VULNERABILITIES
    # How an operator obtains this scanner. Surfaced in the unavailable
    # finding and in --preflight. The agent never installs anything itself.
    install_hint: str = ""
    #: Wall clock this adapter needs. Scanners that query a remote API are
    #: legitimately slower than ones reading a file tree, and an operator
    #: should not have to discover that from a timeout.
    default_timeout_seconds: int = 600

    # ----- availability ----------------------------------------------------

    def configure(self, target: Path, config: Config) -> None:
        """Resolve the command once so probing and execution use the same tool."""
        self._allow_target_executables = target_executables_allowed(config, target)
        self._resolved_command = self._resolve_command(target, self.cfg(config))
        self._target_root = target if target.is_dir() else target.parent

    @property
    def command(self) -> tuple[str, ...]:
        resolved = getattr(self, "_resolved_command", None)
        if resolved is not None:
            return resolved
        found = shutil.which(self.binary) if self.binary else None
        return (found,) if found else ()

    def _resolve_command(self, target: Path, config: ScannerConfig) -> tuple[str, ...]:
        resolved = self._resolve_candidate(target, config)
        if not resolved:
            return ()
        # One containment check for every resolution route, not just the
        # relative-path one. PATH can contain '.' or a tree-local directory, so
        # checking only the explicit-path branch would leave the same door open
        # a step to the left.
        if not getattr(self, "_allow_target_executables", False) and is_within(
            Path(resolved[0]), target
        ):
            return ()
        return resolved

    def _resolve_candidate(self, target: Path, config: ScannerConfig) -> tuple[str, ...]:
        if config.command:
            executable, *arguments = config.command
            candidate = Path(executable).expanduser()
            if candidate.is_absolute() or "/" in executable or "\\" in executable:
                if not candidate.is_absolute():
                    candidate = target / candidate
                candidate = candidate.resolve()
                if candidate.is_file() and os.access(candidate, os.X_OK):
                    return (str(candidate), *arguments)
                return ()
            found = shutil.which(executable)
            return (found, *arguments) if found else ()

        found = shutil.which(self.binary) if self.binary else None
        if found:
            return (found,)
        if self.python_module and importlib.util.find_spec(self.python_module) is not None:
            return (sys.executable, "-m", self.python_module)
        return ()

    def is_available(self) -> bool:
        return bool(self.command)

    def binary_version(self) -> str | None:
        if not self.is_available():
            return None
        try:
            r = subprocess.run(
                [*self.command, self.version_flag],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None
        # A failed probe is not a version. Reporting stderr here put
        # "Error: unknown flag: --version" in the version column of a report
        # that was otherwise claiming the scanner had run fine.
        if r.returncode != 0:
            return None
        # Strip ANSI colour before picking a line, and skip lines that were
        # nothing but colour. njsscan opens its version output with a bare
        # `\x1b[34m` on its own line and puts the version on the next one, so
        # taking the first line recorded the scanner version as `[34m` — in
        # the coverage block, in every report, and in a calibration study
        # whose whole claim is that it re-derives from pinned inputs.
        raw = r.stdout or r.stderr or ""
        for line in _ANSI.sub("", raw).splitlines():
            cleaned = line.strip()
            if cleaned:
                return cleaned
        return None

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

    # ----- subprocess helpers ---------------------------------------------

    def _exec(
        self,
        args: list[str],
        cwd: Path,
        timeout_seconds: int,
        allowed_exits: tuple[int, ...] = (0,),
    ) -> subprocess.CompletedProcess:
        """Run a scanner subprocess with sanitized env, no shell.

        Some scanners (npm audit, pip-audit) exit nonzero on findings; pass
        `allowed_exits` to mark those as success."""
        env = self._sanitized_env()
        try:
            r = subprocess.run(
                args,
                cwd=str(cwd),
                env=env,
                shell=False,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            return subprocess.CompletedProcess(
                args=exc.cmd or args,
                returncode=124,
                stdout="",
                stderr=f"timeout after {timeout_seconds}s",
            )
        if r.returncode not in allowed_exits and r.returncode != 0:
            return r  # caller decides how to handle
        return r

    @staticmethod
    def _sanitized_env() -> dict[str, str]:
        """A minimal env for subprocesses — keep PATH and locale, drop the rest.
        Prevents accidental secret-leak into the scanner process via env."""
        keep = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "TEMP", "TMP")
        return {k: v for k, v in os.environ.items() if k in keep}

    # ----- finding construction helper ------------------------------------

    def _make_finding(
        self,
        *,
        rule_id: str,
        message: str,
        file_path: Path,
        line_start: int,
        line_end: int | None,
        code_snippet: str | None,
        severity: Severity | None = None,
        confidence: Confidence | None = None,
        category: Category | None = None,
        cwe_override: str | None = None,
        scanner_cwe: str | None = None,
        scanner_name: str | None = None,
    ) -> Finding:
        """Construct a canonical Finding from scanner-emitted bits, layering
        in the standards mapping. Scanner-emitted severity wins over the
        map's default; confidence falls back to the map; category is set
        per the map unless explicitly overridden.

        Three sources of a CWE, in descending authority:

        `cwe_override` is the adapter asserting it knows better than both the
        map and the tool — Semgrep uses it, because a Semgrep rule's own
        metadata is more specific than anything we could curate for it.

        The curated `_MAP` comes next. It is reviewed, and it is the only
        source that also carries OWASP, ASVS, SSDF and a fix hint.

        `scanner_cwe` is the last resort: what the tool said about its own
        rule. Bandit publishes a CWE for every plugin and gosec for every
        rule, and we were discarding both — 86% of real corpus findings
        carried no CWE at all while the README led with "Anchored to NIST
        SSDF · OWASP ASVS · OWASP Top 10 · MITRE CWE Top 25". It ranks below
        the curated map because upstream picks a defensible CWE rather than
        the most specific one (Bandit files `assert_used` under CWE-703,
        "improper check for unusual conditions"), but a defensible CWE beats
        none.
        """

        scanner_label = scanner_name or self.name
        entry: StandardsEntry | None = lookup(scanner_label, rule_id)

        # Mapping fallback to wildcard (handled inside lookup).
        canonical_cwe = cwe_override or (entry.canonical_cwe if entry else None) or scanner_cwe
        owasp_top10 = (entry.owasp_top10 if entry else None) or owasp_for_cwe(canonical_cwe)
        asvs_section = entry.asvs_section if entry else None
        nist_ssdf = entry.nist_ssdf if entry else None
        chosen_cat = category or (entry.category if entry else self.default_category)
        chosen_sev = severity or (entry.severity if entry else Severity.MEDIUM)
        chosen_conf = confidence or (entry.confidence if entry else Confidence.MEDIUM)
        short_desc = entry.short_desc if entry else None
        fix_hint = entry.fix_hint if entry else None

        file_path = self._rooted(file_path)

        fingerprint = Finding.make_fingerprint(
            canonical_cwe=canonical_cwe,
            rule_id=rule_id,
            file_path=file_path,
            code_snippet=code_snippet,
        )

        return Finding(
            rule_id=rule_id,
            scanner=scanner_label,
            fingerprint=fingerprint,
            canonical_cwe=canonical_cwe,
            owasp_top10=owasp_top10,
            asvs_section=asvs_section,
            nist_ssdf=nist_ssdf,
            category=chosen_cat,
            severity=chosen_sev,
            confidence=chosen_conf,
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
            code_snippet=code_snippet,
            message=message,
            short_desc=short_desc,
            fix_hint=fix_hint,
            cwe_top25=is_top25(canonical_cwe),
        )

    def _rooted(self, file_path: Path) -> Path:
        """Anchor a scanner-reported path to the audited tree.

        Adapters do not agree on this. Bandit, Semgrep, RuboCop and the rest
        report absolute paths; gitleaks reports paths relative to the
        repository it scanned. Both are reasonable and neither is negotiable
        from here, so the difference is absorbed at the one boundary every
        adapter passes through.

        Leaving it unabsorbed was not cosmetic. Every consumer that answers
        "where is this?" — `is_excluded`, `is_test_path`, the axis split —
        resolves a relative path against the *process* working directory,
        which is wherever the operator happened to invoke the CLI. From there
        `relative_to(root)` raises and the answer comes back "no". So
        `exclude_patterns` silently did not apply to gitleaks findings at all:
        an operator excluding `vendor/` still had vendor secrets scored, and
        the calibration corpus scored four `tests/certs/*.key` files in
        `requests` and six documentation examples in `flask` as production
        secrets, holding both at F.

        A path that is already absolute is returned untouched, including one
        outside the target — an imported SARIF may legitimately name another
        machine's tree, and inventing a root for it would be worse than
        leaving it where it is.
        """
        if file_path.is_absolute():
            return file_path
        root = getattr(self, "_target_root", None)
        return root / file_path if root is not None else file_path

    def _findings_exit_contradiction(
        self,
        target: Path,
        *,
        exit_code: int,
        findings_exit: int,
        findings: list[Finding],
    ) -> str | None:
        """Catch "the scanner said it found things, and we parsed none".

        A findings-signalling exit code is the tool asserting it detected
        something. Recording zero findings in that case reports a clean scan
        of a target the scanner just called dirty — the scanner's own signal,
        silently discarded. Fail the scanner instead, so coverage says we do
        not know rather than saying nothing is there.

        Returns the reason when the contradiction holds, else None. The caller
        turns that into `self.failed(...)` — the helper does not build the
        finding itself, because the outcome is the caller's to state.
        """
        if exit_code != findings_exit or findings:
            return None
        return (
            f"{self.name} exited {exit_code} to signal findings but produced no "
            "parseable results; refusing to record this as a clean scan"
        )

    def _unavailable_finding(self, target: Path) -> Finding:
        """Informational finding emitted when no safe command can be resolved."""
        return Finding(
            rule_id=f"{self.name}.tool_unavailable",
            scanner=self.name,
            fingerprint=f"unavailable.{self.name}",
            canonical_cwe=None,
            owasp_top10=None,
            asvs_section=None,
            nist_ssdf=None,
            category=Category.POLICY_DOCS,
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.HIGH,
            file_path=target,
            line_start=0,
            line_end=None,
            code_snippet=None,
            message=(
                f"Could not resolve {self.name} from its configured command, PATH, "
                "or supported Python module fallback; scan skipped."
            ),
            short_desc=None,
            fix_hint=self.unavailable_fix_hint(),
        )

    def unavailable_fix_hint(self) -> str:
        """Operator-actionable text for a scanner that could not be resolved."""
        install = self.install_hint or f"Install {self.binary}"
        return (
            f"{install}, or set scanners.{self.name}.command to an explicit path, "
            "or supply its SARIF via --sarif-import."
        )

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
