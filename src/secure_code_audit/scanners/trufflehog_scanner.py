"""TruffleHog — secret scanning with verifiers.

Invocation:
  trufflehog filesystem --json --no-update --only-verified <target>

`--only-verified` is the default — high-precision matches where
TruffleHog's verifier confirmed the secret is currently live against
the upstream service. Operators can opt into unverified findings via
`scanners.trufflehog.extra_args: ["--no-only-verified"]` in config.

Output: JSONL (one JSON object per line) — distinct from gitleaks
which writes a single JSON array.
"""

from __future__ import annotations

import json
from pathlib import Path

from secure_code_audit.config import Config
from secure_code_audit.findings import Category, Confidence, Finding, Severity
from secure_code_audit.scanners.base import Scanner


class TruffleHogScanner(Scanner):
    name = "trufflehog"
    binary = "trufflehog"
    default_category = Category.SECRETS

    def run(self, target: Path, config: Config) -> list[Finding]:
        if not self.is_available():
            return [self._unavailable_finding(target)]

        sc_cfg = self.cfg(config)
        args = [
            *self.command,
            "filesystem",
            "--json",
            "--no-update",
            "--only-verified",
            str(target),
        ]
        args.extend(sc_cfg.extra_args)

        r = self._exec(
            args, cwd=target, timeout_seconds=sc_cfg.timeout_seconds, allowed_exits=(0, 183)
        )  # 183 = findings present
        if r.returncode == 124:
            return [
                self._make_finding(
                    rule_id=f"{self.name}.tool_timeout",
                    message=f"trufflehog timed out: {r.stderr[:200]}",
                    file_path=target,
                    line_start=0,
                    line_end=None,
                    code_snippet=None,
                    severity=Severity.INFORMATIONAL,
                    confidence=Confidence.HIGH,
                )
            ]
        if r.returncode not in (0, 183):
            return [
                self._make_finding(
                    rule_id=f"{self.name}.tool_error",
                    message=f"trufflehog failed: {r.stderr[:300]}",
                    file_path=target,
                    line_start=0,
                    line_end=None,
                    code_snippet=None,
                    severity=Severity.INFORMATIONAL,
                    confidence=Confidence.HIGH,
                )
            ]
        if not r.stdout.strip():
            return []

        out: list[Finding] = []
        parse_errors = 0
        for line in r.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                hit = json.loads(line)
            except json.JSONDecodeError:
                parse_errors += 1
                continue
            out.append(self._parse_one(hit))
        if parse_errors:
            out.append(
                self._make_finding(
                    rule_id=f"{self.name}.parse_error",
                    message=f"trufflehog emitted {parse_errors} invalid JSON line(s)",
                    file_path=target,
                    line_start=0,
                    line_end=None,
                    code_snippet=None,
                    severity=Severity.INFORMATIONAL,
                    confidence=Confidence.HIGH,
                )
            )
        return out

    def _parse_one(self, hit: dict) -> Finding:
        detector = str(hit.get("DetectorName") or hit.get("Detector") or "unknown")
        # SourceMetadata.Data.Filesystem.file / line
        meta = ((hit.get("SourceMetadata") or {}).get("Data") or {}).get("Filesystem") or {}
        file_path = Path(meta.get("file") or "")
        line = int(meta.get("line") or 0)
        verified = bool(hit.get("Verified"))
        # The redacted match is what TruffleHog emits when --only-verified
        # is on — it strips the raw secret bytes.
        match = str(hit.get("Redacted") or "<verified>").strip()

        # Verified secrets are CRITICAL; unverified (if operator opted in
        # via --no-only-verified in extra_args) are HIGH.
        severity = Severity.CRITICAL if verified else Severity.HIGH

        return self._make_finding(
            rule_id=f"trufflehog.{detector}",
            message=f"{detector}: {match}".strip(),
            file_path=file_path,
            line_start=line,
            line_end=None,
            code_snippet=match[:200],
            severity=severity,
            confidence=Confidence.HIGH,
            category=Category.SECRETS,
        )
