"""gosec — Go SAST. Optional, because it cannot read Go without Go.

Invocation:
  gosec -fmt=json -no-fail <target>/...

Output: JSON with `Issues[]` (`rule_id`, `severity`, `confidence`, `file`,
`line`, `details`, `code`, `cwe`), a `Stats` block, and a `"Golang errors"` map
keyed by package.

**The reason this adapter is longer than the parse it performs.** gosec loads
packages through `go list`, so on a host with no Go toolchain it does not fail
loudly — it exits 1 having emitted *well-formed* JSON that reads:

    {"Golang errors": {"<pkg>": [{"error": "... go command required, not
     found: exec: \\"go\\": executable file not found in $PATH ..."}]},
     "Issues": [], "Stats": {"files": 0, "lines": 0, "found": 0}}

An adapter that parses `Issues` and returns `[]` reports a clean Go scan of a
repository gosec never opened. That is the exact failure this project exists to
prevent: absence of evidence arriving as evidence of absence. So a run that
loaded no files, or that recorded package errors, is reported as a tool failure
and fails required coverage rather than passing quietly.

**Why optional rather than floor (D12).** Every floor tool parses source
directly and needs only itself to run. gosec needs the *audited project's* own
build tooling to see the code at all — the boundary MA's ADR-012 draws for
SpotBugs, which analyzes compiled bytecode and is therefore unavailable rather
than silent, because the agent never runs a build. Enable gosec where the Go
toolchain is present, which in a Go project's own CI it usually is.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from secure_code_audit.config import Config
from secure_code_audit.findings import Confidence, Finding, Severity
from secure_code_audit.scanner_status import ScanResult
from secure_code_audit.scanners.base import Scanner


class GosecScanner(Scanner):
    name = "gosec"
    binary = "gosec"
    install_hint = "go install github.com/securego/gosec/v2/cmd/gosec@latest"

    def scan(self, target: Path, config: Config) -> ScanResult:
        if not self.is_available():
            return self.unavailable(target)

        sc_cfg = self.cfg(config)
        args = [
            *self.command,
            "-fmt=json",
            # Findings alone must not look like a crash; real failures are
            # detected from the payload below, not from the exit status.
            "-no-fail",
            f"{target}/...",
            *sc_cfg.extra_args,
        ]

        r = self._exec(
            args, cwd=target, timeout_seconds=sc_cfg.timeout_seconds, allowed_exits=(0, 1)
        )
        if r.returncode == 124:
            return self.timed_out(target, f"gosec timed out: {r.stderr}")
        if not r.stdout.strip():
            return self.failed(target, "gosec emitted no output")

        try:
            payload = json.loads(r.stdout)
        except json.JSONDecodeError as e:
            return self.failed(target, f"gosec JSON parse failure: {e}")

        blocked = self._load_failure(payload)
        if blocked is not None:
            return self.failed(target, blocked)

        findings: list[Finding] = []
        for issue in payload.get("Issues") or []:
            if not isinstance(issue, dict):
                continue
            findings.append(self._finding_for(issue))
        return self.completed(findings)

    @staticmethod
    def _load_failure(payload: dict[str, Any]) -> str | None:
        """The reason this run analyzed nothing, or None if it analyzed.

        Checked before findings are read, because both signals here are
        compatible with an empty `Issues` list and only one of them means the
        repository is clean.
        """
        errors = payload.get("Golang errors")
        if isinstance(errors, dict) and errors:
            messages: list[str] = []
            for package, entries in errors.items():
                for entry in entries or []:
                    if isinstance(entry, dict) and entry.get("error"):
                        messages.append(f"{package}: {entry['error']}")
            if messages:
                return "gosec could not load the Go packages: " + "; ".join(messages[:3])

        stats = payload.get("Stats")
        if isinstance(stats, dict) and int(stats.get("files") or 0) == 0:
            # No errors reported and nothing read. Either there is no Go here
            # — in which case applicability should have excluded us — or the
            # load failed silently. Neither is a clean scan.
            return "gosec analyzed zero files, so this is not a clean result"
        return None

    def _finding_for(self, issue: dict[str, Any]) -> Finding:
        cwe = issue.get("cwe")
        cwe_id = cwe.get("id") if isinstance(cwe, dict) else None
        message = str(issue.get("details") or "").strip()
        if cwe_id:
            message = f"{message} (CWE-{cwe_id})" if message else f"CWE-{cwe_id}"
        line = str(issue.get("line") or "0")
        # gosec reports a span as "12-14"; take the ends.
        start, _, end = line.partition("-")
        return self._make_finding(
            rule_id=str(issue.get("rule_id") or "unknown"),
            # gosec declares a CWE per rule. It was being appended to the
            # message text and then dropped on the floor, so the finding
            # carried the id where a human could read it and nowhere the
            # scoring, the Top-25 bonus or the SARIF taxonomy could.
            scanner_cwe=f"CWE-{cwe_id}" if cwe_id else None,
            message=message,
            file_path=Path(str(issue.get("file") or "")),
            line_start=int(start or 0),
            line_end=int(end) if end.isdigit() else None,
            code_snippet=str(issue.get("code") or "").strip() or None,
            severity=Severity.from_string(str(issue.get("severity") or "")),
            confidence=Confidence.from_string(str(issue.get("confidence") or "")),
        )
