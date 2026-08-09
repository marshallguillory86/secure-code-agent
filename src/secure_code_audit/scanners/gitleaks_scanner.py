"""Gitleaks — history-aware secret scanning.

Invocation:
  gitleaks detect --source=<target> --no-banner \
      --redact --report-format=json --report-path=<tmp>

We always pass --redact so the raw secret never reaches the report JSON.
The fingerprint is derived from redacted evidence and the match location.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from secure_code_audit.config import Config
from secure_code_audit.findings import Category, Confidence, Finding, Severity
from secure_code_audit.scanners.base import Scanner


class GitleaksScanner(Scanner):
    name = "gitleaks"
    binary = "gitleaks"
    default_category = Category.SECRETS

    def run(self, target: Path, config: Config) -> list[Finding]:
        if not self.is_available():
            return [self._unavailable_finding(target)]

        sc_cfg = self.cfg(config)
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            report_path = Path(tmp.name)
        try:
            args = [
                *self.command,
                "detect",
                "--source",
                str(target),
                "--no-banner",
                "--redact",
                "--report-format",
                "json",
                "--report-path",
                str(report_path),
            ]
            args.extend(sc_cfg.extra_args)
            # Gitleaks exits 1 when findings exist; 0 = clean; >1 = error.
            r = self._exec(
                args, cwd=target, timeout_seconds=sc_cfg.timeout_seconds, allowed_exits=(0, 1)
            )
            if r.returncode not in (0, 1):
                return [
                    self._make_finding(
                        rule_id=f"{self.name}.tool_error",
                        message=f"gitleaks failed: {r.stderr[:300]}",
                        file_path=target,
                        line_start=0,
                        line_end=None,
                        code_snippet=None,
                        severity=Severity.INFORMATIONAL,
                        confidence=Confidence.HIGH,
                    )
                ]
            if not report_path.exists() or report_path.stat().st_size == 0:
                return []
            try:
                payload = json.loads(report_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                return [
                    self._make_finding(
                        rule_id=f"{self.name}.parse_error",
                        message=f"gitleaks JSON parse failure: {exc}",
                        file_path=target,
                        line_start=0,
                        line_end=None,
                        code_snippet=None,
                        severity=Severity.INFORMATIONAL,
                        confidence=Confidence.HIGH,
                    )
                ]
            return self._parse(payload, target)
        finally:
            report_path.unlink(missing_ok=True)

    def _parse(self, payload: list[dict], target: Path) -> list[Finding]:
        if not isinstance(payload, list):
            return []
        findings: list[Finding] = []
        for hit in payload:
            rule_id = str(hit.get("RuleID") or hit.get("Rule") or "unknown")
            file_path = Path(hit.get("File") or "")
            line = int(hit.get("StartLine") or 0)
            redacted_match = str(hit.get("Match") or hit.get("Secret") or "").strip()
            # Gitleaks --redact returns the match string with the secret
            # replaced by REDACTED — we surface that exact string in the
            # report.
            findings.append(
                self._make_finding(
                    rule_id=f"gitleaks.{rule_id}",
                    message=f"{hit.get('Description') or rule_id}: {redacted_match}".strip(),
                    file_path=file_path,
                    line_start=line,
                    line_end=int(hit.get("EndLine") or line) if hit.get("EndLine") else None,
                    code_snippet=redacted_match[:200] or None,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    category=Category.SECRETS,
                )
            )
        return findings
