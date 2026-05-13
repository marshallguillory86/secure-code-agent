"""Scanner protocol + subprocess helpers."""
from __future__ import annotations

import os
import shutil
import subprocess
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

from secure_code_audit.config import Config, scanner_cfg
from secure_code_audit.findings import Category, Confidence, Finding, Severity
from secure_code_audit.standards import StandardsEntry, is_top25, lookup


class Scanner(ABC):
    """Base class for all scanner adapters.

    Subclasses implement `_run_subprocess()` and `_parse_output()` (or
    override `run()` entirely for built-in / in-process scanners).
    """

    name:         str   # canonical id used in config + reports
    binary:       str   # name of the executable on PATH
    version_flag: str   = "--version"
    default_category: Category = Category.CODE_VULNERABILITIES

    # ----- availability ----------------------------------------------------

    def is_available(self) -> bool:
        return shutil.which(self.binary) is not None

    def binary_version(self) -> Optional[str]:
        if not self.is_available():
            return None
        try:
            r = subprocess.run(
                [self.binary, self.version_flag],
                check=False, capture_output=True, text=True, timeout=10,
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
        cwd:  Path,
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
        rule_id:    str,
        message:    str,
        file_path:  Path,
        line_start: int,
        line_end:   Optional[int],
        code_snippet: Optional[str],
        severity:   Optional[Severity]   = None,
        confidence: Optional[Confidence] = None,
        category:   Optional[Category]   = None,
        cwe_override: Optional[str]      = None,
        scanner_name: Optional[str]      = None,
    ) -> Finding:
        """Construct a canonical Finding from scanner-emitted bits, layering
        in the standards mapping. Scanner-emitted severity wins over the
        map's default; confidence falls back to the map; category is set
        per the map unless explicitly overridden."""

        scanner_label = scanner_name or self.name
        entry: Optional[StandardsEntry] = lookup(scanner_label, rule_id)

        # Mapping fallback to wildcard (handled inside lookup).
        canonical_cwe = cwe_override or (entry.canonical_cwe if entry else None)
        owasp_top10   = entry.owasp_top10 if entry else None
        asvs_section  = entry.asvs_section if entry else None
        nist_ssdf     = entry.nist_ssdf    if entry else None
        chosen_cat    = category or (entry.category if entry else self.default_category)
        chosen_sev    = severity or (entry.severity if entry else Severity.MEDIUM)
        chosen_conf   = confidence or (entry.confidence if entry else Confidence.MEDIUM)
        short_desc    = entry.short_desc if entry else None
        fix_hint      = entry.fix_hint  if entry else None

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
        """Informational finding emitted when the binary isn't on PATH."""
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
            message=f"{self.binary} not on PATH; {self.name} scan skipped.",
            short_desc=None,
            fix_hint=f"Install {self.binary} to enable {self.name} coverage.",
        )

    # ----- shared utility -------------------------------------------------

    def cfg(self, config: Config) -> "ScannerConfig":
        """Convenience accessor."""
        return scanner_cfg(config, self.name)


# Re-export so the registry import in __init__.py is clean.
from secure_code_audit.config import ScannerConfig  # noqa: E402
