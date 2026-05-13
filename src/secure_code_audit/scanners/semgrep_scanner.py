"""Semgrep — multi-language SAST.

Invocation:
  semgrep --config=auto --sarif --metrics=off --error <target>

Output: SARIF 2.1.0. We piggyback the canonical SARIF parser since other
scanners (CodeQL, Snyk, Trivy) emit the same format.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from secure_code_audit.config import Config
from secure_code_audit.findings import Category, Confidence, Finding, Severity
from secure_code_audit.scanners.base import Scanner


class SemgrepScanner(Scanner):
    name   = "semgrep"
    binary = "semgrep"
    default_category = Category.CODE_VULNERABILITIES

    def run(self, target: Path, config: Config) -> list[Finding]:
        if not self.is_available():
            return [self._unavailable_finding(target)]

        sc_cfg = self.cfg(config)
        config_arg = "auto"   # registry-curated pack
        if not sc_cfg.online:
            # Operator opted out of online registry — fall back to bundled
            # rules. Semgrep ships a small offline set under p/python +
            # p/javascript when --config points to those names.
            config_arg = "p/security-audit"

        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as tmp:
            sarif_path = Path(tmp.name)
        try:
            args = [
                self.binary,
                "--config", config_arg,
                "--sarif", "--metrics=off",
                "--output", str(sarif_path),
                str(target),
            ]
            args.extend(sc_cfg.extra_args)
            r = self._exec(args, cwd=target, timeout_seconds=sc_cfg.timeout_seconds,
                           allowed_exits=(0, 1))
            if r.returncode == 124:
                return [self._make_finding(
                    rule_id=f"{self.name}.tool_timeout",
                    message=f"semgrep timed out: {r.stderr[:200]}",
                    file_path=target, line_start=0, line_end=None, code_snippet=None,
                    severity=Severity.INFORMATIONAL, confidence=Confidence.HIGH,
                )]
            if not sarif_path.exists():
                return []
            try:
                payload = json.loads(sarif_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                return []
            return self._parse_sarif(payload, target)
        finally:
            sarif_path.unlink(missing_ok=True)

    # -- minimal SARIF parser; a fuller one lives in sarif.py for ingest --
    def _parse_sarif(self, payload: dict, target: Path) -> list[Finding]:
        findings: list[Finding] = []
        for run in payload.get("runs", []):
            rules = {
                r.get("id"): r
                for r in (run.get("tool", {}).get("driver", {}).get("rules", []) or [])
            }
            for result in run.get("results", []):
                rule_id = result.get("ruleId") or "unknown"
                rule    = rules.get(rule_id, {})
                level   = result.get("level") or rule.get("defaultConfiguration", {}).get("level") or "warning"
                msg     = (result.get("message") or {}).get("text") or rule.get("shortDescription", {}).get("text") or rule_id

                locs = result.get("locations") or []
                if not locs:
                    continue
                loc        = locs[0]
                phys       = loc.get("physicalLocation") or {}
                file_uri   = (phys.get("artifactLocation") or {}).get("uri") or ""
                region     = phys.get("region") or {}
                line_start = int(region.get("startLine") or 0)
                line_end   = int(region.get("endLine") or line_start)
                snippet    = (region.get("snippet") or {}).get("text")

                # SARIF severity: "error" → HIGH, "warning" → MEDIUM, "note" → LOW.
                if level == "error":
                    severity = Severity.HIGH
                elif level == "note":
                    severity = Severity.LOW
                else:
                    severity = Severity.MEDIUM

                # Pull CWE from rule properties.cwe if present.
                cwe = None
                props = rule.get("properties") or {}
                if isinstance(props.get("cwe"), list) and props["cwe"]:
                    cwe = props["cwe"][0]
                elif isinstance(props.get("cwe"), str):
                    cwe = props["cwe"]

                findings.append(self._make_finding(
                    rule_id=rule_id,
                    message=msg,
                    file_path=Path(file_uri) if file_uri else target,
                    line_start=line_start,
                    line_end=line_end if line_end != line_start else None,
                    code_snippet=snippet,
                    severity=severity,
                    confidence=Confidence.MEDIUM,
                    cwe_override=cwe,
                ))
        return findings
