"""Built-in regex rules — high-confidence, low-false-positive patterns that
catch what the big scanners miss or that we want to ship even when no
external scanner is installed.

The rules are opinionated and SMALL. We are not building a parallel
Semgrep. Each rule:
  · targets a single CWE
  · is documented inline (when it's useful + when it false-positives)
  · is covered by at least one true-positive and one false-positive fixture
    in tests/fixtures/builtin_rules/
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import NamedTuple

from secure_code_audit.config import Config
from secure_code_audit.findings import Confidence, Finding, Severity
from secure_code_audit.git_tools import in_scope, is_excluded
from secure_code_audit.scanner_status import ScanResult
from secure_code_audit.scanners.base import Scanner


class _Rule(NamedTuple):
    rule_id: str
    pattern: re.Pattern[str]
    file_globs: tuple[str, ...]  # restrict to certain languages (e.g. ".py")
    description: str


# --- the rule set ---------------------------------------------------------
# Each pattern is tuned for ≥90% precision on real-world code. Update with
# a counter-example in tests/fixtures/ if you tighten or loosen.

_RULES: tuple[_Rule, ...] = (
    _Rule(
        rule_id="sca.python.eval",
        # eval/exec with a non-string-literal first arg. Allow eval('lit').
        #
        # `\b` matched after a dot, so `self.eval(` and `def eval(` both fired.
        # Measured on Django: 28 of 35 hits were `django/template/smartif.py`,
        # which implements the template `if` parser and defines its own `eval`
        # method. A rule that flags a codebase for naming a method `eval` is
        # reporting on vocabulary, not on risk.
        pattern=re.compile(
            r"(?<![\w.])(?<!def )(?:eval|exec)\s*\(\s*(?!['\"][^'\"]*['\"]\s*\))",
            re.MULTILINE,
        ),
        file_globs=(".py",),
        description="eval()/exec() with non-literal input — arbitrary code execution.",
    ),
    _Rule(
        rule_id="sca.python.yaml.unsafe_load",
        pattern=re.compile(
            r"\byaml\.load\s*\(\s*(?!.*Loader\s*=\s*(?:yaml\.)?SafeLoader)",
            re.MULTILINE,
        ),
        file_globs=(".py",),
        description="yaml.load() without SafeLoader — unsafe deserialization.",
    ),
    _Rule(
        rule_id="sca.python.requests.verify_false",
        pattern=re.compile(
            r"\brequests\.(?:get|post|put|patch|delete|head|options|request)\s*\([^)]*verify\s*=\s*False",
            re.MULTILINE | re.DOTALL,
        ),
        file_globs=(".py",),
        description="requests.* called with verify=False — TLS cert validation disabled.",
    ),
    _Rule(
        rule_id="sca.python.subprocess.shell_true",
        pattern=re.compile(
            r"\bsubprocess\.(?:run|call|check_call|check_output|Popen)\s*\([^)]*shell\s*=\s*True",
            re.MULTILINE | re.DOTALL,
        ),
        file_globs=(".py",),
        description="subprocess with shell=True — command-injection risk.",
    ),
    _Rule(
        rule_id="sca.python.fstring_sql",
        # Look for f-strings containing SELECT/INSERT/UPDATE/DELETE
        # interpolated into .execute( / .executemany(. We require both the
        # f-string AND the execute-call to be within ~200 chars to keep
        # false positives down.
        pattern=re.compile(
            r"\.(?:execute|executemany)\s*\(\s*f['\"](?:[^'\"]*?\b(?:SELECT|INSERT|UPDATE|DELETE|MERGE)\b[^'\"]*?\{[^}]+\})",
            re.IGNORECASE | re.MULTILINE,
        ),
        file_globs=(".py",),
        description="f-string SQL in .execute()/.executemany() — possible SQL injection.",
    ),
    _Rule(
        rule_id="sca.python.hashlib.md5_sha1_security",
        # MD5/SHA-1 — false-positives in non-security use are common. We
        # only flag when usedforsecurity is not explicitly False.
        pattern=re.compile(
            r"\bhashlib\.(?:md5|sha1)\s*\((?![^)]*usedforsecurity\s*=\s*False)",
            re.MULTILINE,
        ),
        file_globs=(".py",),
        description="MD5/SHA-1 without usedforsecurity=False — weak hash for security context.",
    ),
    _Rule(
        rule_id="sca.web.dangerously_set_inner_html",
        pattern=re.compile(
            r"dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:",
            re.MULTILINE,
        ),
        file_globs=(".tsx", ".jsx", ".ts", ".js"),
        description="React dangerouslySetInnerHTML — XSS surface unless input is trusted/sanitized.",
    ),
    _Rule(
        rule_id="sca.web.cors_wildcard",
        # Headers/middleware setting Allow-Origin '*'. Pair with
        # Allow-Credentials: true → spec violation + XSCSRF surface.
        pattern=re.compile(
            r"(?i)Access-Control-Allow-Origin\s*['\"]?\s*[:=]\s*['\"]?\*",
        ),
        file_globs=(".py", ".js", ".ts", ".tsx", ".go", ".rb", ".java"),
        description="CORS Allow-Origin: * — review for credentialed-cookies exposure.",
    ),
    _Rule(
        rule_id="sca.shell.curl_pipe_sh",
        pattern=re.compile(
            r"\bcurl\b[^|;\n]+\|\s*(?:bash|sh|zsh)\b",
            re.MULTILINE,
        ),
        file_globs=(".sh", "Dockerfile"),
        description="curl ... | sh — unauthenticated remote-script execution.",
    ),
)


class BuiltinRulesScanner(Scanner):
    name = "builtin_rules"
    binary = ""  # in-process scanner

    def is_available(self) -> bool:
        return True  # no external binary needed

    def binary_version(self) -> str | None:
        from secure_code_audit import __version__

        return f"builtin/{__version__}"

    def scan(self, target: Path, config: Config) -> ScanResult:
        findings: list[Finding] = []
        for path in self._candidate_files(target, config):
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for rule in _RULES:
                if not self._applies_to(path, rule):
                    continue
                for m in rule.pattern.finditer(text):
                    line_start = text.count("\n", 0, m.start()) + 1
                    line_end = text.count("\n", 0, m.end()) + 1
                    snippet = m.group(0)[:200]
                    findings.append(
                        self._make_finding(
                            rule_id=rule.rule_id,
                            message=rule.description,
                            file_path=path,
                            line_start=line_start,
                            line_end=line_end if line_end != line_start else None,
                            code_snippet=snippet,
                            severity=Severity.HIGH,
                            confidence=Confidence.MEDIUM,
                        )
                    )
        return self.completed(findings)

    def _applies_to(self, path: Path, rule: _Rule) -> bool:
        name = path.name
        for glob in rule.file_globs:
            if glob.startswith("."):
                if name.endswith(glob):
                    return True
            elif name == glob:
                return True
        return False

    def _candidate_files(self, target: Path, config: Config):
        for path in target.rglob("*"):
            if not path.is_file():
                continue
            if is_excluded(path, target, config.exclude_patterns):
                continue
            if not in_scope(path, config.include_extensions):
                continue
            yield path
