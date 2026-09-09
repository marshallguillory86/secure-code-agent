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
from secure_code_audit.scanner_status import ScanResult
from secure_code_audit.scanners.base import Scanner

_FINDINGS_EXIT = 1  # gitleaks: 0 = clean, 1 = leaks found, >1 = error


class GitleaksScanner(Scanner):
    name = "gitleaks"
    binary = "gitleaks"
    default_category = Category.SECRETS
    install_hint = "brew install gitleaks, or a pinned release from github.com/gitleaks/gitleaks"

    def scan(self, target: Path, config: Config) -> ScanResult:
        if not self.is_available():
            return self.unavailable(target)

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
                return self.failed(target, f"gitleaks failed: {r.stderr[:300]}")
            if not report_path.exists() or report_path.stat().st_size == 0:
                # Exit 0 with no report is a genuinely clean scan. Exit 1 with
                # no report is gitleaks telling us it found secrets and us
                # having nothing to show for it.
                contradiction = self._findings_exit_contradiction(
                    target, exit_code=r.returncode, findings_exit=_FINDINGS_EXIT, findings=[]
                )
                return self.failed(target, contradiction) if contradiction else self.completed([])
            try:
                payload = json.loads(report_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                return self.failed(target, f"gitleaks JSON parse failure: {exc}")
            if not isinstance(payload, list):
                return self.failed(target, "gitleaks report root must be a JSON array")
            findings = self._parse(payload, target)
            contradiction = self._findings_exit_contradiction(
                target, exit_code=r.returncode, findings_exit=_FINDINGS_EXIT, findings=findings
            )
            return self.failed(target, contradiction) if contradiction else self.completed(findings)
        finally:
            report_path.unlink(missing_ok=True)

    def _parse(self, payload: list[dict], target: Path) -> list[Finding]:
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
