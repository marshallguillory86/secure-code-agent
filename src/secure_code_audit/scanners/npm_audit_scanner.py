"""npm audit — Node SCA.

Invocation:
  npm audit --json --omit=dev [--audit-level=low]

npm audit exits nonzero when findings exist; we accept 0+1.
"""

from __future__ import annotations

import json
from pathlib import Path

from secure_code_audit.config import Config
from secure_code_audit.findings import Category, Confidence, Finding, Severity
from secure_code_audit.scanner_status import ScanResult
from secure_code_audit.scanners.base import Scanner

_NPM_SEVERITY: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFORMATIONAL,
}


class NpmAuditScanner(Scanner):
    name = "npm_audit"
    binary = "npm"
    default_category = Category.DEPENDENCIES
    install_hint = "Install Node.js from nodejs.org so npm is on PATH"

    def scan(self, target: Path, config: Config) -> ScanResult:
        if not self.is_available():
            return self.unavailable(target)

        pkg_dirs = self._discover_package_dirs(target, config.exclude_patterns)
        if not pkg_dirs:
            return self.not_applicable(
                target, "No package-lock.json found in scope; npm audit skipped."
            )

        sc_cfg = self.cfg(config)
        findings: list[Finding] = []
        # One audit per package directory, and any of them can fail on its own.
        # A repository where three lockfiles audited cleanly and a fourth timed
        # out has not been audited, so the failures are collected and the whole
        # run reports FAILED — while the findings that were parsed are kept.
        failures: list[str] = []
        timeouts: list[str] = []
        for pkg_dir in pkg_dirs:
            args = [*self.command, "audit", "--json", "--omit=dev"]
            args.extend(sc_cfg.extra_args)
            r = self._exec(
                args, cwd=pkg_dir, timeout_seconds=sc_cfg.timeout_seconds, allowed_exits=(0, 1)
            )
            if r.returncode == 124:
                timeouts.append(f"npm audit timed out in {pkg_dir}")
                continue
            if r.returncode not in (0, 1):
                failures.append(f"npm audit failed in {pkg_dir}: {r.stderr[:300]}")
                continue
            if not r.stdout.strip():
                failures.append(f"npm audit emitted no JSON in {pkg_dir}")
                continue
            try:
                payload = json.loads(r.stdout)
            except json.JSONDecodeError as exc:
                failures.append(f"npm audit JSON parse failure in {pkg_dir}: {exc}")
                continue
            findings.extend(self._parse(payload, pkg_dir))
        if failures:
            return self.failed(target, "; ".join(failures + timeouts), findings=findings)
        if timeouts:
            return self.timed_out(target, "; ".join(timeouts))
        return self.completed(findings)

    def _discover_package_dirs(self, root: Path, excludes: tuple[str, ...]) -> list[Path]:
        out: list[Path] = []
        for path in root.rglob("package-lock.json"):
            rel = str(path.relative_to(root).as_posix())
            if any(rel.startswith(e) or f"/{e}" in f"/{rel}" for e in excludes):
                continue
            out.append(path.parent)
        return out

    def _parse(self, payload: dict, pkg_dir: Path) -> list[Finding]:
        findings: list[Finding] = []
        vulns = payload.get("vulnerabilities") or {}
        manifest = pkg_dir / "package-lock.json"
        for pkg_name, info in vulns.items():
            severity_str = (info.get("severity") or "moderate").lower()
            severity = _NPM_SEVERITY.get(severity_str, Severity.MEDIUM)
            via = info.get("via") or []
            advisories = [v for v in via if isinstance(v, dict)]
            if not advisories:
                # Indirect-only entry; collapse to a single finding.
                findings.append(
                    self._make_finding(
                        rule_id=f"npm_audit.{pkg_name}.indirect",
                        message=f"{pkg_name}: vulnerable via transitive dep.",
                        file_path=manifest,
                        line_start=0,
                        line_end=None,
                        code_snippet=None,
                        severity=severity,
                        confidence=Confidence.HIGH,
                        category=Category.DEPENDENCIES,
                    )
                )
                continue
            for adv in advisories:
                rule_id = f"npm_audit.{adv.get('source') or adv.get('name') or pkg_name}"
                msg = adv.get("title") or adv.get("name") or pkg_name
                url = adv.get("url") or ""
                findings.append(
                    self._make_finding(
                        rule_id=rule_id,
                        message=f"{pkg_name}: {msg} {url}".strip(),
                        file_path=manifest,
                        line_start=0,
                        line_end=None,
                        code_snippet=None,
                        severity=severity,
                        confidence=Confidence.HIGH,
                        category=Category.DEPENDENCIES,
                    )
                )
        return findings
