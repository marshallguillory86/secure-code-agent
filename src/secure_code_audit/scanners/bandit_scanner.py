"""Bandit — Python SAST.

Invocation:
  bandit -r <target> -f json -ll -ii [--exclude <pattern>]

Output: JSON with results[] array. Each result has filename, line_number,
test_id (B102, B608, ...), issue_text, issue_severity, issue_confidence,
and code (the offending snippet).
"""

from __future__ import annotations

import json
from pathlib import Path

from secure_code_audit.config import Config
from secure_code_audit.findings import Confidence, Finding, Severity
from secure_code_audit.scanners.base import Scanner


class BanditScanner(Scanner):
    name = "bandit"
    binary = "bandit"
    python_module = "bandit"

    def run(self, target: Path, config: Config) -> list[Finding]:
        if not self.is_available():
            return [self._unavailable_finding(target)]

        sc_cfg = self.cfg(config)
        args = [
            *self.command,
            "--quiet",
            "-r",
            str(target),
            "-f",
            "json",
            "--severity-level",
            "low",
            "--confidence-level",
            "low",
        ]
        excludes = self._bandit_excludes(target, config.exclude_patterns)
        if excludes:
            # Bandit accepts a single comma-separated exclude value. Repeating
            # --exclude causes argparse to retain only the final occurrence.
            args.extend(["--exclude", ",".join(excludes)])
        args.extend(sc_cfg.extra_args)

        # Bandit exits nonzero on findings — accept 0 + 1.
        r = self._exec(
            args, cwd=target, timeout_seconds=sc_cfg.timeout_seconds, allowed_exits=(0, 1)
        )
        if r.returncode == 124:
            return [self._timeout_finding(target, r.stderr)]
        if not r.stdout.strip():
            return [self._error_finding(target, "bandit emitted no output")]

        try:
            payload = json.loads(r.stdout)
        except json.JSONDecodeError as e:
            return [self._error_finding(target, f"bandit JSON parse failure: {e}")]

        findings: list[Finding] = []
        for result in payload.get("results", []):
            rule_id = result.get("test_id") or result.get("test_name") or "unknown"
            findings.append(
                self._make_finding(
                    rule_id=rule_id,
                    message=str(result.get("issue_text") or "").strip(),
                    file_path=Path(result.get("filename", "")),
                    line_start=int(result.get("line_number") or 0),
                    line_end=int(result.get("line_range", [0])[-1] or 0)
                    if isinstance(result.get("line_range"), list)
                    else None,
                    code_snippet=str(result.get("code") or "").strip() or None,
                    severity=Severity.from_string(result.get("issue_severity", "")),
                    confidence=Confidence.from_string(result.get("issue_confidence", "")),
                )
            )
        return findings

    @staticmethod
    def _bandit_excludes(target: Path, patterns: tuple[str, ...]) -> list[str]:
        """Translate repository-relative excludes to Bandit's path globs."""
        root = target if target.is_dir() else target.parent
        excludes: list[str] = []
        for pattern in patterns:
            candidate = Path(pattern).expanduser()
            if not candidate.is_absolute():
                candidate = root / candidate
            value = str(candidate)
            if pattern.endswith(("/", "\\")):
                value += "/*"
            excludes.append(value)
        return excludes

    def _timeout_finding(self, target: Path, stderr: str) -> Finding:
        return self._make_finding(
            rule_id=f"{self.name}.tool_timeout",
            message=f"bandit timed out: {stderr}",
            file_path=target,
            line_start=0,
            line_end=None,
            code_snippet=None,
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.HIGH,
        )

    def _error_finding(self, target: Path, message: str) -> Finding:
        return self._make_finding(
            rule_id=f"{self.name}.tool_error",
            message=message,
            file_path=target,
            line_start=0,
            line_end=None,
            code_snippet=None,
            severity=Severity.INFORMATIONAL,
            confidence=Confidence.HIGH,
        )
