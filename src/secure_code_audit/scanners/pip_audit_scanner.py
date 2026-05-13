"""pip-audit — Python SCA via PyPI Advisory DB / OSV.

Invocation:
  pip-audit -r requirements.txt --format=json

Output: JSON with dependencies[] each having vulns[] with id, fix_versions,
description.
"""
from __future__ import annotations

import json
from pathlib import Path

from secure_code_audit.config import Config
from secure_code_audit.findings import Category, Confidence, Finding, Severity
from secure_code_audit.scanners.base import Scanner


_REQ_NAMES: tuple[str, ...] = (
    "requirements.txt",
    "requirements-dev.txt",
    "requirements/base.txt",
)


class PipAuditScanner(Scanner):
    name   = "pip_audit"
    binary = "pip-audit"
    default_category = Category.DEPENDENCIES

    def run(self, target: Path, config: Config) -> list[Finding]:
        if not self.is_available():
            return [self._unavailable_finding(target)]

        req_files = [target / r for r in _REQ_NAMES if (target / r).exists()]
        if not req_files:
            return [self._make_finding(
                rule_id=f"{self.name}.no_requirements",
                message="No requirements.txt found at target root; pip-audit skipped.",
                file_path=target, line_start=0, line_end=None, code_snippet=None,
                severity=Severity.INFORMATIONAL, confidence=Confidence.HIGH,
                category=Category.DEPENDENCIES,
            )]

        sc_cfg = self.cfg(config)
        findings: list[Finding] = []
        for req in req_files:
            args = [self.binary, "-r", str(req), "--format=json"]
            args.extend(sc_cfg.extra_args)
            r = self._exec(args, cwd=target, timeout_seconds=sc_cfg.timeout_seconds,
                           allowed_exits=(0, 1))
            if r.returncode == 124:
                findings.append(self._make_finding(
                    rule_id=f"{self.name}.tool_timeout",
                    message=f"pip-audit timed out on {req.name}: {r.stderr}",
                    file_path=req, line_start=0, line_end=None, code_snippet=None,
                    severity=Severity.INFORMATIONAL, confidence=Confidence.HIGH,
                ))
                continue
            if not r.stdout.strip():
                continue
            try:
                payload = json.loads(r.stdout)
            except json.JSONDecodeError:
                continue

            deps = payload.get("dependencies", payload if isinstance(payload, list) else [])
            for dep in deps:
                name    = dep.get("name", "?")
                version = dep.get("version", "?")
                for vuln in dep.get("vulns", []) or []:
                    vuln_id  = vuln.get("id", "UNKNOWN")
                    fixes    = vuln.get("fix_versions") or []
                    desc     = (vuln.get("description") or "").strip()
                    fix_note = f" Fix in: {', '.join(fixes)}" if fixes else " No fix available."
                    findings.append(self._make_finding(
                        rule_id=f"pip_audit.{vuln_id}",
                        message=f"{name} {version} — {vuln_id}: {desc[:200]}{fix_note}",
                        file_path=req, line_start=0, line_end=None, code_snippet=None,
                        severity=Severity.HIGH, confidence=Confidence.HIGH,
                        category=Category.DEPENDENCIES,
                    ))
        return findings
