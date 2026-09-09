"""pip-audit — Python dependency auditing via PyPI or OSV advisories."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from secure_code_audit.config import Config, ScannerConfig
from secure_code_audit.findings import Category, Confidence, Finding, Severity
from secure_code_audit.git_tools import is_excluded
from secure_code_audit.scanner_status import ScanResult
from secure_code_audit.scanners.base import Scanner

_MODES = {"auto", "requirements", "project", "locked", "environment"}


@dataclass(frozen=True)
class _AuditInput:
    path: Path
    args: tuple[str, ...]


class PipAuditScanner(Scanner):
    name = "pip_audit"
    binary = "pip-audit"
    python_module = "pip_audit"
    default_category = Category.DEPENDENCIES
    install_hint = "pip install 'secure-code-agent[required-scanners]'"

    def scope(self, config: ScannerConfig) -> str | None:
        """What this run audited: the mode, its inputs, any extra arguments.

        pip-audit's answer depends entirely on what it was pointed at, so a
        report that omits this is not reproducible. The orchestrator used to
        special-case this scanner by name to supply it.
        """
        parts = [f"mode={config.mode}"]
        if config.inputs:
            parts.append(f"inputs={','.join(config.inputs)}")
        if config.extra_args:
            parts.append(f"extra_args={' '.join(config.extra_args)}")
        return "; ".join(parts)

    def scan(self, target: Path, config: Config) -> ScanResult:
        if not self.is_available():
            return self.unavailable(target)

        sc_cfg = self.cfg(config)
        if sc_cfg.mode not in _MODES:
            return self.failed(
                target,
                f"unsupported pip_audit mode {sc_cfg.mode!r}; choose one of {sorted(_MODES)}",
            )

        try:
            audit_inputs = self._audit_inputs(target, config)
        except ValueError as exc:
            return self.failed(target, str(exc))
        if not audit_inputs:
            return self.not_applicable(
                target, "No supported Python dependency input found; pip-audit skipped."
            )

        findings: list[Finding] = []
        # Each input can fail independently, and a partial audit is not an
        # audit. Failures are collected and the findings are kept. Timeouts are
        # tracked apart from other failures so a slow input still reports
        # TIMED_OUT — both fail coverage, but only one tells you to raise the
        # timeout.
        failures: list[str] = []
        timeouts: list[str] = []
        for audit_input in audit_inputs:
            args = [*self.command, *audit_input.args, "--format=json", *sc_cfg.extra_args]
            result = self._exec(
                args,
                cwd=target,
                timeout_seconds=sc_cfg.timeout_seconds,
                allowed_exits=(0, 1),
            )
            if result.returncode == 124:
                timeouts.append(f"pip-audit timed out on {audit_input.path}")
                continue
            if result.returncode not in (0, 1):
                failures.append(f"pip-audit failed on {audit_input.path}: {result.stderr[:300]}")
                continue
            if not result.stdout.strip():
                failures.append(f"pip-audit emitted no JSON for {audit_input.path}")
                continue
            try:
                payload = json.loads(result.stdout)
                findings.extend(self._parse(payload, audit_input.path))
            except json.JSONDecodeError as exc:
                failures.append(f"pip-audit JSON parse failure for {audit_input.path}: {exc}")
                continue
            except ValueError as exc:
                # JSONDecodeError subclasses ValueError, so it is caught above
                # first; this is _parse rejecting a shape it cannot read.
                failures.append(f"{exc} (for {audit_input.path})")
                continue
        if failures:
            return self.failed(target, "; ".join(failures + timeouts), findings=findings)
        if timeouts:
            return self.timed_out(target, "; ".join(timeouts))
        return self.completed(findings, scope=self.scope(sc_cfg))

    def _audit_inputs(self, target: Path, config: Config) -> list[_AuditInput]:
        sc_cfg = self.cfg(config)
        explicit = self._explicit_inputs(target, sc_cfg.inputs)
        if sc_cfg.mode == "environment":
            if explicit:
                raise ValueError("pip_audit environment mode does not accept inputs")
            return [_AuditInput(path=target, args=())]

        if explicit:
            paths = explicit
        elif sc_cfg.mode == "requirements":
            paths = self._discover_requirements(target, config.exclude_patterns)
        else:
            paths = self._discover_projects(target, config.exclude_patterns)
            if sc_cfg.mode == "auto":
                requirements = self._discover_requirements(target, config.exclude_patterns)
                covered_dirs = {path.parent for path in requirements}
                projects = [path for path in paths if path.parent not in covered_dirs]
                paths = [*requirements, *projects]

        if sc_cfg.mode == "requirements":
            return [self._requirement_input(path) for path in paths]
        if sc_cfg.mode == "locked":
            return [self._project_input(path, locked=True) for path in paths]
        if sc_cfg.mode == "project":
            return [self._project_input(path, locked=False) for path in paths]

        return [
            self._requirement_input(path)
            if path.name.startswith("requirements")
            else self._project_input(path, locked=False)
            for path in paths
        ]

    @staticmethod
    def _explicit_inputs(target: Path, inputs: list[str]) -> list[Path]:
        paths: list[Path] = []
        for value in inputs:
            path = Path(value).expanduser()
            if not path.is_absolute():
                path = target / path
            path = path.resolve()
            if not path.exists():
                raise ValueError(f"configured pip_audit input does not exist: {value}")
            paths.append(path)
        return paths

    @staticmethod
    def _discover_requirements(target: Path, excludes: tuple[str, ...]) -> list[Path]:
        return sorted(
            path
            for path in target.rglob("requirements*.txt")
            if path.is_file() and not is_excluded(path, target, excludes)
        )

    @staticmethod
    def _discover_projects(target: Path, excludes: tuple[str, ...]) -> list[Path]:
        return sorted(
            path
            for path in target.rglob("pyproject.toml")
            if path.is_file() and not is_excluded(path, target, excludes)
        )

    @staticmethod
    def _requirement_input(path: Path) -> _AuditInput:
        return _AuditInput(path=path, args=("-r", str(path)))

    @staticmethod
    def _project_input(path: Path, *, locked: bool) -> _AuditInput:
        project = path if path.is_dir() else path.parent
        args = ("--locked", str(project)) if locked else (str(project),)
        return _AuditInput(path=path, args=args)

    def _parse(self, payload: object, source: Path) -> list[Finding]:
        """Raises ValueError on a payload shape we cannot read.

        The caller turns that into a recorded failure. Returning a control
        finding from here would have made this function the thing that decides
        the run's outcome, which is what `ScanResult` exists to stop.
        """
        if isinstance(payload, dict):
            dependencies = payload.get("dependencies", [])
        elif isinstance(payload, list):
            dependencies = payload
        else:
            raise ValueError("pip-audit JSON root must be an object or array")

        findings: list[Finding] = []
        for dependency in dependencies:
            name = dependency.get("name", "?")
            version = dependency.get("version", "?")
            for vulnerability in dependency.get("vulns", []) or []:
                vuln_id = vulnerability.get("id", "UNKNOWN")
                fixes = vulnerability.get("fix_versions") or []
                description = (vulnerability.get("description") or "").strip()
                fix_note = f" Fix in: {', '.join(fixes)}" if fixes else " No fix available."
                findings.append(
                    self._make_finding(
                        rule_id=f"pip_audit.{vuln_id}",
                        message=f"{name} {version} — {vuln_id}: {description[:200]}{fix_note}",
                        file_path=source,
                        line_start=0,
                        line_end=None,
                        code_snippet=None,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        category=Category.DEPENDENCIES,
                    )
                )
        return findings
