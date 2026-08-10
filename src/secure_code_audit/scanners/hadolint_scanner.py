"""Hadolint — Dockerfile linter.

Invocation:
  hadolint --no-fail --format json <Dockerfile> [<Dockerfile> ...]

Hadolint emits a JSON array — one entry per finding with file/line/code
(rule id like DL3001) / level / message. We walk the target tree for
Dockerfiles and pass them all to one hadolint invocation.

Only a subset of DL/SC rules have security implications; we map those
in standards.py (see SECURITY_RELEVANT_RULES). Style-only rules
(DL3007, DL3008 unpinned-apt) are tagged config_iac at LOW severity.
"""

from __future__ import annotations

import json
from pathlib import Path

from secure_code_audit.config import Config
from secure_code_audit.findings import Category, Confidence, Finding, Severity
from secure_code_audit.git_tools import is_excluded
from secure_code_audit.scanners.base import Scanner

# Hadolint rule ids whose semantics are security-relevant. The category
# stays config_iac but severity is bumped over the default LOW.
_HIGH_SECURITY: dict[str, Severity] = {
    "DL3002": Severity.HIGH,  # USER root
    "DL3004": Severity.MEDIUM,  # do not use sudo
    "DL3025": Severity.MEDIUM,  # use JSON form for CMD/ENTRYPOINT (shell injection surface)
    "DL4006": Severity.MEDIUM,  # set SHELL with pipefail
    "SC2086": Severity.MEDIUM,  # unquoted variable (shell-injection)
    "SC2046": Severity.MEDIUM,  # unquoted command substitution
    "DL3023": Severity.MEDIUM,  # COPY --from points to its own FROM alias
    "DL3033": Severity.MEDIUM,  # specify version with yum install -y
    "DL3008": Severity.LOW,  # pin apt versions
    "DL3009": Severity.LOW,  # delete apt lists after install
    "DL3015": Severity.LOW,  # use --no-install-recommends
    "DL3018": Severity.LOW,  # pin apk versions
}


class HadolintScanner(Scanner):
    name = "hadolint"
    binary = "hadolint"
    default_category = Category.CONFIG_IAC
    install_hint = "brew install hadolint, or a pinned release from github.com/hadolint/hadolint"

    def run(self, target: Path, config: Config) -> list[Finding]:
        if not self.is_available():
            return [self._unavailable_finding(target)]

        dockerfiles = self._find_dockerfiles(target, config.exclude_patterns)
        if not dockerfiles:
            return [
                self._make_finding(
                    rule_id=f"{self.name}.no_dockerfiles",
                    message="No Dockerfiles found in scope; hadolint skipped.",
                    file_path=target,
                    line_start=0,
                    line_end=None,
                    code_snippet=None,
                    severity=Severity.INFORMATIONAL,
                    confidence=Confidence.HIGH,
                    category=Category.CONFIG_IAC,
                )
            ]

        sc_cfg = self.cfg(config)
        args = [*self.command, "--no-fail", "--format", "json"]
        args.extend(str(p) for p in dockerfiles)
        args.extend(sc_cfg.extra_args)

        r = self._exec(args, cwd=target, timeout_seconds=sc_cfg.timeout_seconds, allowed_exits=(0,))
        if r.returncode == 124:
            return [
                self._make_finding(
                    rule_id=f"{self.name}.tool_timeout",
                    message=f"hadolint timed out: {r.stderr[:200]}",
                    file_path=target,
                    line_start=0,
                    line_end=None,
                    code_snippet=None,
                    severity=Severity.INFORMATIONAL,
                    confidence=Confidence.HIGH,
                )
            ]
        if r.returncode != 0:
            return [
                self._make_finding(
                    rule_id=f"{self.name}.tool_error",
                    message=f"hadolint failed: {r.stderr[:300]}",
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

        try:
            payload = json.loads(r.stdout)
        except json.JSONDecodeError as exc:
            return [
                self._make_finding(
                    rule_id=f"{self.name}.parse_error",
                    message=f"hadolint JSON parse failure: {exc}",
                    file_path=target,
                    line_start=0,
                    line_end=None,
                    code_snippet=None,
                    severity=Severity.INFORMATIONAL,
                    confidence=Confidence.HIGH,
                )
            ]
        if not isinstance(payload, list):
            return [
                self._make_finding(
                    rule_id=f"{self.name}.parse_error",
                    message="hadolint JSON root must be an array",
                    file_path=target,
                    line_start=0,
                    line_end=None,
                    code_snippet=None,
                    severity=Severity.INFORMATIONAL,
                    confidence=Confidence.HIGH,
                )
            ]

        return [self._parse_one(item) for item in payload if isinstance(item, dict)]

    def _find_dockerfiles(self, target: Path, excludes) -> list[Path]:
        out: list[Path] = []
        for path in target.rglob("Dockerfile*"):
            if not path.is_file():
                continue
            if is_excluded(path, target, excludes):
                continue
            out.append(path)
        return out

    def _parse_one(self, item: dict) -> Finding:
        code = str(item.get("code") or "unknown")
        severity = _HIGH_SECURITY.get(code, Severity.LOW)
        finding = self._make_finding(
            rule_id=f"hadolint.{code}",
            message=str(item.get("message") or code),
            file_path=Path(item.get("file") or ""),
            line_start=int(item.get("line") or 0),
            line_end=None,
            code_snippet=None,
            severity=severity,
            confidence=Confidence.HIGH,
            category=Category.CONFIG_IAC,
        )
        return finding
