"""Scanner subprocesses. Each module is a single-purpose adapter:
  in:  scanner invocation + target path
  out: list[Finding] in the canonical schema (see secure_code_audit.findings).

The registry below is the lookup the CLI uses to enumerate active scanners.
"""
from __future__ import annotations

from typing import Callable, Iterable

from secure_code_audit.findings import Finding

from secure_code_audit.scanners.base import Scanner
from secure_code_audit.scanners.bandit_scanner    import BanditScanner
from secure_code_audit.scanners.builtin_rules     import BuiltinRulesScanner
from secure_code_audit.scanners.gitleaks_scanner  import GitleaksScanner
from secure_code_audit.scanners.npm_audit_scanner import NpmAuditScanner
from secure_code_audit.scanners.pip_audit_scanner import PipAuditScanner
from secure_code_audit.scanners.semgrep_scanner   import SemgrepScanner

SCANNERS: dict[str, type[Scanner]] = {
    "bandit":         BanditScanner,
    "builtin_rules":  BuiltinRulesScanner,
    "gitleaks":       GitleaksScanner,
    "npm_audit":      NpmAuditScanner,
    "pip_audit":      PipAuditScanner,
    "semgrep":        SemgrepScanner,
}


def all_scanner_names() -> list[str]:
    return list(SCANNERS.keys())


def get(name: str) -> type[Scanner] | None:
    return SCANNERS.get(name)
