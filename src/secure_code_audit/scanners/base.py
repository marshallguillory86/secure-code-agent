"""Scanner protocol + subprocess helpers."""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
from abc import ABC, abstractmethod
from pathlib import Path

from secure_code_audit.config import Config, scanner_cfg
from secure_code_audit.findings import Category, Confidence, Finding, Severity
from secure_code_audit.standards import StandardsEntry, is_top25, lookup


class Scanner(ABC):
    """Base class for all scanner adapters.

    Subclasses implement `_run_subprocess()` and `_parse_output()` (or
    override `run()` entirely for built-in / in-process scanners).
    """

    name: str  # canonical id used in config + reports
    binary: str  # name of the executable on PATH
    version_flag: str = "--version"
    python_module: str | None = None
    default_category: Category = Category.CODE_VULNERABILITIES
    # How an operator obtains this scanner. Surfaced in the unavailable
    # finding and in --preflight. The agent never installs anything itself.
    install_hint: str = ""

    # ----- availability ----------------------------------------------------

    def configure(self, target: Path, config: Config) -> None:
        """Resolve the command once so probing and execution use the same tool."""
        self._resolved_command = self._resolve_command(target, self.cfg(config))

    @property
    def command(self) -> tuple[str, ...]:
        resolved = getattr(self, "_resolved_command", None)
        if resolved is not None:
            return resolved
        found = shutil.which(self.binary) if self.binary else None
        return (found,) if found else ()

    def _resolve_command(self, target: Path, config: ScannerConfig) -> tuple[str, ...]:
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
        out = (r.stdout or r.stderr or "").strip().splitlines()
        return out[0] if out else None

    # ----- main entrypoint ------------------------------------------------

    @abstractmethod
    def run(self, target: Path, config: Config) -> list[Finding]:
        """Execute the scanner against target. MUST NOT raise.

        Errors are converted to a single informational finding so the
        audit pipeline never dies on a single scanner failing.
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
        scanner_name: str | None = None,
    ) -> Finding:
        """Construct a canonical Finding from scanner-emitted bits, layering
        in the standards mapping. Scanner-emitted severity wins over the
        map's default; confidence falls back to the map; category is set
        per the map unless explicitly overridden."""

        scanner_label = scanner_name or self.name
        entry: StandardsEntry | None = lookup(scanner_label, rule_id)

        # Mapping fallback to wildcard (handled inside lookup).
        canonical_cwe = cwe_override or (entry.canonical_cwe if entry else None)
        owasp_top10 = entry.owasp_top10 if entry else None
        asvs_section = entry.asvs_section if entry else None
        nist_ssdf = entry.nist_ssdf if entry else None
        chosen_cat = category or (entry.category if entry else self.default_category)
        chosen_sev = severity or (entry.severity if entry else Severity.MEDIUM)
        chosen_conf = confidence or (entry.confidence if entry else Confidence.MEDIUM)
        short_desc = entry.short_desc if entry else None
        fix_hint = entry.fix_hint if entry else None

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

    # ----- shared utility -------------------------------------------------

    def cfg(self, config: Config) -> ScannerConfig:
        """Convenience accessor."""
        return scanner_cfg(config, self.name)


# Re-export so the registry import in __init__.py is clean.
from secure_code_audit.config import ScannerConfig  # noqa: E402
