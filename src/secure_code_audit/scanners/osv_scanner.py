"""OSV-Scanner — multi-ecosystem SCA via osv.dev.

Invocation:
  osv-scanner scan source --format=json --recursive <target>

Output: JSON with `results[].packages[].vulnerabilities[]` each carrying
id (CVE / GHSA / OSV-), severity, summary, references.

Overlaps with pip-audit + npm-audit by design. Stable fingerprints support
baselines, but the current scorer does not deduplicate across scanners.
"""

from __future__ import annotations

import json
from pathlib import Path

from secure_code_audit.config import Config
from secure_code_audit.findings import Category, Confidence, Finding, Severity
from secure_code_audit.scanners.base import Scanner

_OSV_SEVERITY: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.MEDIUM,
}


class OsvScanner(Scanner):
    name = "osv_scanner"
    binary = "osv-scanner"
    default_category = Category.DEPENDENCIES
    install_hint = (
        "brew install osv-scanner, or a pinned release from github.com/google/osv-scanner"
    )

    def run(self, target: Path, config: Config) -> list[Finding]:
        if not self.is_available():
            return [self._unavailable_finding(target)]

        sc_cfg = self.cfg(config)
        args = [
            *self.command,
            "scan",
            "source",
            "--format=json",
            "--recursive",
            str(target),
        ]
        args.extend(sc_cfg.extra_args)

        # osv-scanner exits 1 on findings, 0 on clean, 127 on bad usage,
        # 128 on internal error.
        r = self._exec(
            args, cwd=target, timeout_seconds=sc_cfg.timeout_seconds, allowed_exits=(0, 1)
        )
        if r.returncode == 124:
            return [
                self._make_finding(
                    rule_id=f"{self.name}.tool_timeout",
                    message=f"osv-scanner timed out: {r.stderr[:200]}",
                    file_path=target,
                    line_start=0,
                    line_end=None,
                    code_snippet=None,
                    severity=Severity.INFORMATIONAL,
                    confidence=Confidence.HIGH,
                )
            ]
        if r.returncode not in (0, 1):
            return [
                self._make_finding(
                    rule_id=f"{self.name}.tool_error",
                    message=f"osv-scanner failed: {r.stderr[:300]}",
                    file_path=target,
                    line_start=0,
                    line_end=None,
                    code_snippet=None,
                    severity=Severity.INFORMATIONAL,
                    confidence=Confidence.HIGH,
                )
            ]
        if not r.stdout.strip():
            return [
                self._make_finding(
                    rule_id=f"{self.name}.tool_error",
                    message="osv-scanner emitted no JSON",
                    file_path=target,
                    line_start=0,
                    line_end=None,
                    code_snippet=None,
                    severity=Severity.INFORMATIONAL,
                    confidence=Confidence.HIGH,
                )
            ]

        try:
            payload = json.loads(r.stdout)
        except json.JSONDecodeError as exc:
            return [
                self._make_finding(
                    rule_id=f"{self.name}.parse_error",
                    message=f"osv-scanner JSON parse failure: {exc}",
                    file_path=target,
                    line_start=0,
                    line_end=None,
                    code_snippet=None,
                    severity=Severity.INFORMATIONAL,
                    confidence=Confidence.HIGH,
                )
            ]

        return self._parse(payload, target)

    def _parse(self, payload: dict, target: Path) -> list[Finding]:
        out: list[Finding] = []
        for result in payload.get("results", []):
            source = (result.get("source") or {}).get("path") or ""
            file_path = Path(source) if source else target
            for pkg_block in result.get("packages", []):
                pkg = pkg_block.get("package") or {}
                pkg_name = pkg.get("name", "?")
                pkg_ver = pkg.get("version", "?")
                for vuln in pkg_block.get("vulnerabilities", []) or []:
                    vid = str(vuln.get("id") or "UNKNOWN")
                    summary = (vuln.get("summary") or "").strip()[:300]
                    severity_str = self._extract_severity(vuln)
                    severity = _OSV_SEVERITY.get(severity_str, Severity.MEDIUM)
                    out.append(
                        self._make_finding(
                            rule_id=f"osv_scanner.{vid}",
                            message=f"{pkg_name} {pkg_ver} — {vid}: {summary}",
                            file_path=file_path,
                            line_start=0,
                            line_end=None,
                            code_snippet=None,
                            severity=severity,
                            confidence=Confidence.HIGH,
                            category=Category.DEPENDENCIES,
                        )
                    )
        return out

    def _extract_severity(self, vuln: dict) -> str:
        """OSV format puts severity in two places: a top-level
        `database_specific.severity` (string) and a `severity[]` array
        with CVSS vectors. Prefer the string when present."""
        ds = (vuln.get("database_specific") or {}).get("severity")
        if isinstance(ds, str):
            return ds.upper()
        sev_arr = vuln.get("severity") or []
        if isinstance(sev_arr, list) and sev_arr:
            # CVSS string in score; we don't parse the vector — fall back
            # to MEDIUM as a safe default.
            return "MEDIUM"
        return "UNKNOWN"
