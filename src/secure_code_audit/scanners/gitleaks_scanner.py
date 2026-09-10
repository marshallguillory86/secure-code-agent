"""Gitleaks — secret scanning of the working tree *and* git history.

Invocation, twice:
  gitleaks dir <target> --no-banner --redact --report-format=json ...
  gitleaks git <target> --no-banner --redact --report-format=json ...

**Both, because either alone is wrong.** This adapter used to run only
`detect --source`, which in gitleaks 8 scans commits and nothing else. A
plaintext key sitting in the working tree, not yet committed, produced
"no leaks found" — the most damaging way for a secret scanner to be wrong,
and the moment catching it is worth most. Verified against a fixture: a
private key in an uncommitted file is invisible to `detect` and to `git`,
and found by `dir`.

Dropping history in exchange would be no better. A credential committed and
later deleted is still in the object store and still needs rotating; that is
what "history-aware" in the old docstring was reaching for, and it is a real
capability rather than an accident.

The two passes overlap on anything committed and unchanged. That is handled
downstream by `merge_corroborating`, which collapses one weakness reported at
one line and records the second sighting rather than counting it twice.

A non-git target gets the `dir` pass only, stated in the scope rather than
treated as a failure — auditing an extracted tarball is supported.

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
        root = target if target.is_dir() else target.parent
        passes = ["dir"]
        if (root / ".git").exists():
            passes.append("git")

        findings: list[Finding] = []
        for mode in passes:
            outcome = self._one_pass(mode, target, sc_cfg)
            if isinstance(outcome, str):
                return self.failed(target, outcome)
            findings.extend(outcome)

        scope = (
            "working tree and git history"
            if "git" in passes
            else "working tree (not a git repository)"
        )
        return self.completed(findings, scope=scope)

    def _one_pass(self, mode: str, target: Path, sc_cfg) -> list[Finding] | str:
        """One gitleaks invocation. Returns its findings, or a failure reason.

        A reason rather than a raised exception because `scan()` must not
        raise, and rather than an empty list because "found nothing" and
        "could not look" are the distinction this whole tool exists to keep.
        """
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            report_path = Path(tmp.name)
        try:
            args = [
                *self.command,
                mode,
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
                return f"gitleaks {mode} failed: {r.stderr[:300]}"
            if not report_path.exists() or report_path.stat().st_size == 0:
                # Exit 0 with no report is a genuinely clean scan. Exit 1 with
                # no report is gitleaks telling us it found secrets and us
                # having nothing to show for it.
                return (
                    self._findings_exit_contradiction(
                        target, exit_code=r.returncode, findings_exit=_FINDINGS_EXIT, findings=[]
                    )
                    or []
                )
            try:
                payload = json.loads(report_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                return f"gitleaks {mode} JSON parse failure: {exc}"
            if not isinstance(payload, list):
                return f"gitleaks {mode} report root must be a JSON array"
            parsed = self._parse(payload, target)
            return (
                self._findings_exit_contradiction(
                    target,
                    exit_code=r.returncode,
                    findings_exit=_FINDINGS_EXIT,
                    findings=parsed,
                )
                or parsed
            )
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
