"""OpenSSF Scorecard — repo + supply-chain hygiene.

Special case among scanners:
  · Operates on a REMOTE repo URL, not a local path.
  · Needs the GH_TOKEN env var (or equivalent) to query GitHub APIs.
  · Best run on the repo root, not on a subdirectory.

Invocation:
  scorecard --repo=<github-url> --format=json --show-details

Output: JSON with `checks[]` array, each having `name`, `score` (0-10
or -1 for inconclusive), `reason`, `details[]`, and `documentation.url`.

We map each Scorecard check into `supply_chain` (or `policy_docs` for
documentation-style checks). Score → severity mapping:
  · score < 0       → INFORMATIONAL (inconclusive — check couldn't run)
  · score < 3       → HIGH          (clearly failing)
  · score < 7       → MEDIUM        (warning)
  · score < 10      → LOW           (acceptable but not perfect)
  · score == 10     → no finding emitted (passed cleanly)
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from secure_code_audit.config import Config
from secure_code_audit.findings import Category, Confidence, Finding, Severity
from secure_code_audit.scanners.base import Scanner

# Checks whose semantics are "documentation present" rather than
# supply-chain integrity.
_POLICY_DOCS_CHECKS = {"Security-Policy", "License", "CII-Best-Practices"}


class ScorecardScanner(Scanner):
    name = "scorecard"
    binary = "scorecard"
    default_category = Category.SUPPLY_CHAIN
    install_hint = "brew install scorecard, or a pinned release from github.com/ossf/scorecard"

    def run(self, target: Path, config: Config) -> list[Finding]:
        if not self.is_available():
            return [self._unavailable_finding(target)]

        repo_url = self._infer_repo_url(target)
        if repo_url is None:
            return [
                self._make_finding(
                    rule_id=f"{self.name}.no_remote",
                    message="Scorecard requires a remote GitHub URL (origin remote not found).",
                    file_path=target,
                    line_start=0,
                    line_end=None,
                    code_snippet=None,
                    severity=Severity.INFORMATIONAL,
                    confidence=Confidence.HIGH,
                    category=Category.SUPPLY_CHAIN,
                )
            ]

        sc_cfg = self.cfg(config)
        args = [
            *self.command,
            f"--repo={repo_url}",
            "--format=json",
            "--show-details",
        ]
        args.extend(sc_cfg.extra_args)

        r = self._exec(
            args, cwd=target, timeout_seconds=sc_cfg.timeout_seconds, allowed_exits=(0, 1, 2)
        )
        if r.returncode == 124:
            return [
                self._make_finding(
                    rule_id=f"{self.name}.tool_timeout",
                    message=f"scorecard timed out: {r.stderr[:200]}",
                    file_path=target,
                    line_start=0,
                    line_end=None,
                    code_snippet=None,
                    severity=Severity.INFORMATIONAL,
                    confidence=Confidence.HIGH,
                )
            ]
        if r.returncode not in (0, 1, 2):
            return [
                self._make_finding(
                    rule_id=f"{self.name}.tool_error",
                    message=f"scorecard failed: {r.stderr[:300]}",
                    file_path=target,
                    line_start=0,
                    line_end=None,
                    code_snippet=None,
                    severity=Severity.INFORMATIONAL,
                    confidence=Confidence.HIGH,
                )
            ]
        if not r.stdout.strip():
            return [
                self._make_finding(
                    rule_id=f"{self.name}.tool_error",
                    message="scorecard emitted no JSON",
                    file_path=target,
                    line_start=0,
                    line_end=None,
                    code_snippet=None,
                    severity=Severity.INFORMATIONAL,
                    confidence=Confidence.HIGH,
                )
            ]

        try:
            payload = json.loads(r.stdout)
        except json.JSONDecodeError as exc:
            return [
                self._make_finding(
                    rule_id=f"{self.name}.parse_error",
                    message=f"scorecard JSON parse failure: {exc}",
                    file_path=target,
                    line_start=0,
                    line_end=None,
                    code_snippet=None,
                    severity=Severity.INFORMATIONAL,
                    confidence=Confidence.HIGH,
                )
            ]

        return self._parse(payload, target)

    def _infer_repo_url(self, target: Path) -> str | None:
        """Run `git remote get-url origin` in target. Returns the URL
        normalized to https://github.com/<owner>/<repo> form, or None
        if no GitHub origin is present."""
        git = shutil.which("git")
        if git is None:
            return None
        try:
            r = subprocess.run(
                [git, "remote", "get-url", "origin"],
                cwd=str(target),
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None
        url = (r.stdout or "").strip()
        if not url:
            return None
        # Normalize SSH form to HTTPS form so scorecard accepts it.
        if url.startswith("git@github.com:"):
            url = "https://github.com/" + url[len("git@github.com:") :]
        if url.endswith(".git"):
            url = url[:-4]
        if not url.startswith("https://github.com/"):
            return None
        return url

    def _parse(self, payload: dict, target: Path) -> list[Finding]:
        out: list[Finding] = []
        for check in payload.get("checks", []):
            name = str(check.get("name") or "Unknown")
            score = check.get("score")
            reason = (check.get("reason") or "").strip()
            doc = (check.get("documentation") or {}).get("url") or ""

            severity = self._score_to_severity(score)
            if severity is None:
                continue  # passed cleanly, no finding

            category = (
                Category.POLICY_DOCS if name in _POLICY_DOCS_CHECKS else Category.SUPPLY_CHAIN
            )
            msg = f"OpenSSF Scorecard `{name}` scored {score}/10: {reason}"
            if doc:
                msg = f"{msg} [{doc}]"

            out.append(
                self._make_finding(
                    rule_id=f"scorecard.{name}",
                    message=msg,
                    file_path=target,
                    line_start=0,
                    line_end=None,
                    code_snippet=None,
                    severity=severity,
                    confidence=Confidence.HIGH,
                    category=category,
                )
            )
        return out

    @staticmethod
    def _score_to_severity(score) -> Severity | None:
        if score is None:
            return None
        try:
            s = int(score)
        except (TypeError, ValueError):
            return None
        if s < 0:
            return Severity.INFORMATIONAL
        if s == 10:
            return None
        if s < 3:
            return Severity.HIGH
        if s < 7:
            return Severity.MEDIUM
        return Severity.LOW
