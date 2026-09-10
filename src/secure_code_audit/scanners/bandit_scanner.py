"""Bandit — Python SAST.

Invocation:
  bandit -r <target> -f json -ll -ii [--exclude <pattern>]

Output: JSON with results[] array. Each result has filename, line_number,
test_id (B102, B608, ...), issue_text, issue_severity, issue_confidence,
code (the offending snippet), and issue_cwe.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from secure_code_audit.config import Config
from secure_code_audit.findings import Confidence, Finding, Severity
from secure_code_audit.scanner_status import ScanResult
from secure_code_audit.scanners.base import Scanner


def _cwe_of(result: dict[str, Any]) -> str | None:
    """Bandit's own CWE for the plugin that fired.

    Every Bandit plugin declares one, and we were discarding all of them.
    Seven Bandit rules are curated in `standards.py` against roughly seventy
    the tool ships, so 86% of real corpus findings carried no CWE while the
    README led with "Anchored to … MITRE CWE Top 25".

    The curated map still wins where it exists — it is reviewed and it also
    carries OWASP, ASVS, SSDF and a fix hint, none of which Bandit emits.
    """
    cwe = result.get("issue_cwe")
    if not isinstance(cwe, dict):
        return None
    identifier = cwe.get("id")
    return f"CWE-{identifier}" if identifier else None


class BanditScanner(Scanner):
    name = "bandit"
    binary = "bandit"
    python_module = "bandit"
    install_hint = "pip install 'secure-code-agent[required-scanners]'"

    def scan(self, target: Path, config: Config) -> ScanResult:
        if not self.is_available():
            return self.unavailable(target)

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
            return self.timed_out(target, f"bandit timed out: {r.stderr}")
        if not r.stdout.strip():
            return self.failed(target, "bandit emitted no output")

        try:
            payload = json.loads(r.stdout)
        except json.JSONDecodeError as e:
            return self.failed(target, f"bandit JSON parse failure: {e}")

        findings: list[Finding] = []
        for result in payload.get("results", []):
            rule_id = result.get("test_id") or result.get("test_name") or "unknown"
            findings.append(
                self._make_finding(
                    rule_id=rule_id,
                    scanner_cwe=_cwe_of(result),
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
        return self.completed(findings)

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
