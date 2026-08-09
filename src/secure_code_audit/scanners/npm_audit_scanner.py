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

    def run(self, target: Path, config: Config) -> list[Finding]:
        if not self.is_available():
            return [self._unavailable_finding(target)]

        pkg_dirs = self._discover_package_dirs(target, config.exclude_patterns)
        if not pkg_dirs:
            return [
                self._make_finding(
                    rule_id=f"{self.name}.no_package_lock",
                    message="No package-lock.json found in scope; npm audit skipped.",
                    file_path=target,
                    line_start=0,
                    line_end=None,
                    code_snippet=None,
                    severity=Severity.INFORMATIONAL,
                    confidence=Confidence.HIGH,
                    category=Category.DEPENDENCIES,
                )
            ]

        sc_cfg = self.cfg(config)
        findings: list[Finding] = []
        for pkg_dir in pkg_dirs:
            args = [*self.command, "audit", "--json", "--omit=dev"]
            args.extend(sc_cfg.extra_args)
            r = self._exec(
                args, cwd=pkg_dir, timeout_seconds=sc_cfg.timeout_seconds, allowed_exits=(0, 1)
            )
            if r.returncode == 124:
                findings.append(
                    self._control_finding(
                        target, "tool_timeout", f"npm audit timed out in {pkg_dir}"
                    )
                )
                continue
            if r.returncode not in (0, 1):
                findings.append(
                    self._control_finding(
                        target, "tool_error", f"npm audit failed in {pkg_dir}: {r.stderr[:300]}"
                    )
                )
                continue
            if not r.stdout.strip():
                findings.append(
                    self._control_finding(
                        target, "tool_error", f"npm audit emitted no JSON in {pkg_dir}"
                    )
                )
                continue
            try:
                payload = json.loads(r.stdout)
            except json.JSONDecodeError as exc:
                findings.append(
                    self._control_finding(
                        target, "parse_error", f"npm audit JSON parse failure in {pkg_dir}: {exc}"
                    )
                )
                continue
            findings.extend(self._parse(payload, pkg_dir))
        return findings

    def _control_finding(self, target: Path, suffix: str, message: str) -> Finding:
        return self._make_finding(
            rule_id=f"{self.name}.{suffix}",
            message=message,
            file_path=target,
            line_start=0,
            line_end=None,
            code_snippet=None,
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.HIGH,
            category=Category.DEPENDENCIES,
        )

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
