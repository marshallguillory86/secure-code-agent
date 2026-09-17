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
from secure_code_audit.scanner_status import ScanResult
from secure_code_audit.scanners.base import Scanner

#: osv-scanner's exit code for "No package sources found" — no lockfile,
#: manifest or SBOM anywhere under the target. Nothing to read is not a
#: failure to read, so it becomes NOT_APPLICABLE (D23). The tool's own
#: `--allow-no-lockfiles` would turn this into exit 0 instead, which would
#: report a completed run over nothing; an outcome that says so is better.
_NO_PACKAGE_SOURCES = 128

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

    def scan(self, target: Path, config: Config) -> ScanResult:
        if not self.is_available():
            return self.unavailable(target)

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

        # osv-scanner exits 0 on clean, 1 on findings, 127 on general failure,
        # and 128 when it found nothing to read. 128 was documented here as an
        # internal error and mapped to FAILED — see D23.
        r = self._exec(
            args, cwd=target, timeout_seconds=sc_cfg.timeout_seconds, allowed_exits=(0, 1)
        )
        if r.returncode == 124:
            return self.timed_out(target, f"osv-scanner timed out: {r.stderr[:200]}")
        if r.returncode == _NO_PACKAGE_SOURCES:
            return self.not_applicable(
                target, "osv-scanner found no package sources (lockfile, manifest or SBOM) to scan"
            )
        if r.returncode not in (0, 1):
            return self.failed(target, f"osv-scanner failed: {r.stderr[:300]}")
        if not r.stdout.strip():
            return self.failed(target, "osv-scanner emitted no JSON")

        try:
            payload = json.loads(r.stdout)
        except json.JSONDecodeError as exc:
            return self.failed(target, f"osv-scanner JSON parse failure: {exc}")

        return self.completed(self._parse(payload, target))

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
