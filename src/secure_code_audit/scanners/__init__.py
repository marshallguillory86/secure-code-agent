"""Scanner subprocesses. Each module is a single-purpose adapter:
  in:  scanner invocation + target path
  out: list[Finding] in the canonical schema (see secure_code_audit.findings).

The registry below is the lookup the CLI uses to enumerate active scanners.
"""

from __future__ import annotations

from secure_code_audit.scanners.bandit_scanner import BanditScanner
from secure_code_audit.scanners.base import Scanner
from secure_code_audit.scanners.builtin_rules import BuiltinRulesScanner
from secure_code_audit.scanners.checkov_scanner import CheckovScanner
from secure_code_audit.scanners.gitleaks_scanner import GitleaksScanner
from secure_code_audit.scanners.hadolint_scanner import HadolintScanner
from secure_code_audit.scanners.npm_audit_scanner import NpmAuditScanner
from secure_code_audit.scanners.osv_scanner import OsvScanner
from secure_code_audit.scanners.pip_audit_scanner import PipAuditScanner
from secure_code_audit.scanners.scorecard_scanner import ScorecardScanner
from secure_code_audit.scanners.semgrep_scanner import SemgrepScanner
from secure_code_audit.scanners.trivy_scanner import TrivyScanner
from secure_code_audit.scanners.trufflehog_scanner import TruffleHogScanner

SCANNERS: dict[str, type[Scanner]] = {
    # Tier-1 — Python / Node / secrets / SAST
    "bandit": BanditScanner,
    "builtin_rules": BuiltinRulesScanner,
    "gitleaks": GitleaksScanner,
    "npm_audit": NpmAuditScanner,
    "pip_audit": PipAuditScanner,
    "semgrep": SemgrepScanner,
    # Tier-2 — IaC / containers / supply chain / multi-ecosystem SCA / verified secrets
    "checkov": CheckovScanner,
    "hadolint": HadolintScanner,
    "osv_scanner": OsvScanner,
    "scorecard": ScorecardScanner,
    "trivy": TrivyScanner,
    "trufflehog": TruffleHogScanner,
}


def all_scanner_names() -> list[str]:
    return list(SCANNERS.keys())


def get(name: str) -> type[Scanner] | None:
    return SCANNERS.get(name)
