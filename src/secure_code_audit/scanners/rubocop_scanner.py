"""RuboCop — Ruby security cops.

Invocation:
  rubocop --only Security --format json --force-default-config <target>

Output: JSON with `files[]`, each holding `offenses[]` carrying `cop_name`,
`message`, `severity` and a `location` with `start_line` / `last_line`.

Why `--only Security`. RuboCop is a style linter that happens to ship a
Security department, and running it whole would bury three real findings under
a thousand formatting opinions. Restricting to `Security` is what makes it a
security scanner rather than a noise source, and it is how the coverage claim
in D12 was measured.

Why `--force-default-config`. The audited repository's own `.rubocop.yml` is
repository content, and D1 draws the line at executing what the tree supplies:
a config there can disable cops, and `require:` a Ruby file that RuboCop then
loads and runs. Ignoring the tree's config keeps a scanned repository from
choosing what gets found in it — the point of a security gate.

Why it is in the floor (D12). Brakeman, the tool people name first for Ruby,
analyzes Rails applications and reports nothing on plain Ruby. RuboCop's
Security cops are the only FOSS coverage of Ruby security primitives in
ordinary source, and measured against `tests/fixtures/semgrep-offline` they
flag `eval`, `Marshal.load` and `YAML.load` with no findings on the safe twins.
They do not flag `instance_eval` or `class_eval`, which is why the offline
profile still carries one Ruby code-injection rule.
"""

from __future__ import annotations

import json
from pathlib import Path

from secure_code_audit.config import Config
from secure_code_audit.findings import Confidence, Finding, Severity
from secure_code_audit.scanner_status import ScanResult
from secure_code_audit.scanners.base import Scanner

#: RuboCop's severities are linter severities, not security ones. A Security
#: cop firing is a real finding whatever RuboCop calls it, so `convention` —
#: which is what most of them report — must not arrive as INFORMATIONAL and
#: fall out of the gate.
_SEVERITY_BY_RUBOCOP: dict[str, Severity] = {
    "fatal": Severity.CRITICAL,
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "convention": Severity.MEDIUM,
    "refactor": Severity.LOW,
    "info": Severity.LOW,
}


class RubocopScanner(Scanner):
    name = "rubocop"
    binary = "rubocop"
    install_hint = "gem install rubocop"

    def scan(self, target: Path, config: Config) -> ScanResult:
        if not self.is_available():
            return self.unavailable(target)

        sc_cfg = self.cfg(config)
        args = [
            *self.command,
            "--only",
            "Security",
            "--format",
            "json",
            "--force-default-config",
            str(target),
            *sc_cfg.extra_args,
        ]

        # RuboCop exits 1 when it has offenses, 0 when clean.
        r = self._exec(
            args, cwd=target, timeout_seconds=sc_cfg.timeout_seconds, allowed_exits=(0, 1)
        )
        if r.returncode == 124:
            return self.timed_out(target, f"rubocop timed out: {r.stderr}")
        if not r.stdout.strip():
            return self.failed(target, "rubocop emitted no output")

        try:
            payload = json.loads(r.stdout)
        except json.JSONDecodeError as e:
            return self.failed(target, f"rubocop JSON parse failure: {e}")

        findings: list[Finding] = []
        for entry in payload.get("files") or []:
            if not isinstance(entry, dict):
                continue
            file_path = Path(str(entry.get("path") or ""))
            for offense in entry.get("offenses") or []:
                if not isinstance(offense, dict):
                    continue
                findings.append(self._finding_for(offense, file_path))
        return self.completed(findings)

    def _finding_for(self, offense: dict, file_path: Path) -> Finding:
        location = offense.get("location")
        location = location if isinstance(location, dict) else {}
        start = location.get("start_line") or location.get("line") or 0
        end = location.get("last_line")
        return self._make_finding(
            rule_id=str(offense.get("cop_name") or "unknown"),
            message=str(offense.get("message") or "").strip(),
            file_path=file_path,
            line_start=int(start),
            line_end=int(end) if end else None,
            code_snippet=None,
            severity=_SEVERITY_BY_RUBOCOP.get(
                str(offense.get("severity") or "").lower(), Severity.MEDIUM
            ),
            # A Security cop is a syntactic match on a known-dangerous call,
            # with no dataflow behind it — the same standing as njsscan's.
            confidence=Confidence.MEDIUM,
        )
