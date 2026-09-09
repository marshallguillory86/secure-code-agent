"""njsscan — offline Node/JavaScript SAST.

Invocation:
  njsscan --json <target>

Output: JSON keyed by finding *category* rather than by finding. Both `nodejs`
and `templates` map a rule id to a single object holding `metadata` (shared by
every occurrence) and `files` (one entry per occurrence, with `match_lines`,
`match_position` and `match_string`). Flattening that back into one finding per
occurrence is most of this adapter.

Why it is in the floor (D12). It is a Python package that carries its own
rules, so it installs alongside this tool and needs no registry and no Node
runtime — a JavaScript repository can be scanned on a host with no Node on it
at all. Measured against `tests/fixtures/semgrep-offline`, it flags md5, sha1,
`Math.random` and `process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'` with no
findings on the safe twins.

What it does not cover, and why our offline profile still carries JavaScript
rules: njsscan's `eval`, `child_process.exec` and DOM-XSS rules are taint rules
gated on an Express handler shape — `function ($REQ, $RES, ...)` with a
`$REQ.$QUERY` source. In a CLI script, a library or a Lambda handler there is
no such shape and those rules are silent.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from secure_code_audit.config import Config
from secure_code_audit.findings import Confidence, Finding, Severity
from secure_code_audit.scanner_status import ScanResult
from secure_code_audit.scanners.base import Scanner


class NjsscanScanner(Scanner):
    name = "njsscan"
    binary = "njsscan"
    python_module = "njsscan"
    install_hint = "pip install 'secure-code-agent[required-scanners]'"

    #: The two top-level buckets njsscan reports under. `templates` covers
    #: Pug/Handlebars/EJS and friends; both share the same inner shape.
    _BUCKETS = ("nodejs", "templates")

    def scan(self, target: Path, config: Config) -> ScanResult:
        if not self.is_available():
            return self.unavailable(target)

        sc_cfg = self.cfg(config)
        args = [*self.command, "--json", str(target), *sc_cfg.extra_args]

        # njsscan exits 1 when it has findings, 0 when clean.
        r = self._exec(
            args, cwd=target, timeout_seconds=sc_cfg.timeout_seconds, allowed_exits=(0, 1)
        )
        if r.returncode == 124:
            return self.timed_out(target, f"njsscan timed out: {r.stderr}")
        if not r.stdout.strip():
            return self.failed(target, "njsscan emitted no output")

        try:
            payload = json.loads(r.stdout)
        except json.JSONDecodeError as e:
            return self.failed(target, f"njsscan JSON parse failure: {e}")

        findings: list[Finding] = []
        for bucket in self._BUCKETS:
            section = payload.get(bucket)
            if not isinstance(section, dict):
                continue
            for rule_id, entry in section.items():
                findings.extend(self._findings_for_rule(str(rule_id), entry))
        return self.completed(findings)

    def _findings_for_rule(self, rule_id: str, entry: Any) -> list[Finding]:
        if not isinstance(entry, dict):
            return []
        metadata = entry.get("metadata")
        metadata = metadata if isinstance(metadata, dict) else {}
        message = str(metadata.get("description") or rule_id).strip()
        severity = Severity.from_string(str(metadata.get("severity") or ""))

        out: list[Finding] = []
        for occurrence in entry.get("files") or []:
            if not isinstance(occurrence, dict):
                continue
            # `match_lines` is [start, end]; a single-line match repeats itself.
            lines = occurrence.get("match_lines")
            start, end = (lines + [None, None])[:2] if isinstance(lines, list) else (None, None)
            out.append(
                self._make_finding(
                    rule_id=rule_id,
                    message=message,
                    file_path=Path(str(occurrence.get("file_path") or "")),
                    line_start=int(start or 0),
                    line_end=int(end) if end else None,
                    code_snippet=str(occurrence.get("match_string") or "").strip() or None,
                    severity=severity,
                    # njsscan reports no per-finding confidence. Its rules are
                    # pattern matches over syntax, not inference, so claiming
                    # HIGH would be inventing a signal the tool never sent.
                    confidence=Confidence.MEDIUM,
                )
            )
        return out
