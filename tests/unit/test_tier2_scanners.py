"""Tier-2 scanner adapters — Trivy, Checkov, Hadolint, OSV-Scanner,
TruffleHog, Scorecard. Uses fixture JSON/SARIF inputs and patches the
subprocess invocation so tests don't depend on the binaries being
installed."""

import json
from pathlib import Path
from subprocess import CompletedProcess

from secure_code_audit.config import Config
from secure_code_audit.findings import Category, Severity
from secure_code_audit.scanner_status import (
    CoverageStatus,
    ScannerOutcome,
    classify_execution,
    evaluate_coverage,
)
from secure_code_audit.scanners.checkov_scanner import CheckovScanner
from secure_code_audit.scanners.hadolint_scanner import HadolintScanner
from secure_code_audit.scanners.osv_scanner import OsvScanner
from secure_code_audit.scanners.scorecard_scanner import ScorecardScanner
from secure_code_audit.scanners.trivy_scanner import TrivyScanner
from secure_code_audit.scanners.trufflehog_scanner import TruffleHogScanner

# --- common helpers -------------------------------------------------------


def _proc(stdout: str = "", stderr: str = "", code: int = 0) -> CompletedProcess:
    return CompletedProcess(args=["scanner"], returncode=code, stdout=stdout, stderr=stderr)


def _mock_available(monkeypatch, scanner_cls, available=True):
    monkeypatch.setattr(scanner_cls, "is_available", lambda self: available)


# --- Trivy ----------------------------------------------------------------


def test_trivy_unavailable_emits_info(tmp_path, monkeypatch):
    _mock_available(monkeypatch, TrivyScanner, available=False)
    findings = TrivyScanner().run(tmp_path, Config())
    assert len(findings) == 1
    assert findings[0].severity is Severity.INFORMATIONAL
    assert "trivy" in findings[0].rule_id


def test_trivy_parses_sarif_and_routes_categories(tmp_path, monkeypatch):
    _mock_available(monkeypatch, TrivyScanner)

    # Minimal SARIF the ingest expects — emitted to the temp path.
    sarif_content = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "Trivy", "rules": []}},
                "results": [
                    {
                        "ruleId": "CVE-2024-12345",
                        "level": "error",
                        "message": {"text": "vulnerable lib"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "go.mod"},
                                    "region": {"startLine": 5},
                                }
                            }
                        ],
                    },
                    {
                        "ruleId": "AVD-AWS-0021",
                        "level": "warning",
                        "message": {"text": "S3 bucket public"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "main.tf"},
                                    "region": {"startLine": 12},
                                }
                            }
                        ],
                    },
                ],
            }
        ],
    }

    def fake_exec(self, args, cwd, timeout_seconds, allowed_exits=(0,)):
        # The scanner writes to a tempfile via --output; mimic that.
        out_idx = args.index("--output") + 1
        Path(args[out_idx]).write_text(json.dumps(sarif_content), encoding="utf-8")
        return _proc(code=0)

    monkeypatch.setattr(TrivyScanner, "_exec", fake_exec)
    findings = TrivyScanner().run(tmp_path, Config())
    assert {f.canonical_cwe for f in findings} >= {None, "CWE-1104"} or len(findings) == 2

    cats = {f.category for f in findings}
    assert Category.DEPENDENCIES in cats
    assert Category.CONFIG_IAC in cats


# --- Checkov --------------------------------------------------------------


def test_checkov_unavailable_emits_info(tmp_path, monkeypatch):
    _mock_available(monkeypatch, CheckovScanner, available=False)
    findings = CheckovScanner().run(tmp_path, Config())
    assert findings[0].severity is Severity.INFORMATIONAL


def test_checkov_parses_sarif_into_config_iac(tmp_path, monkeypatch):
    _mock_available(monkeypatch, CheckovScanner)

    sarif_content = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "Checkov", "rules": []}},
                "results": [
                    {
                        "ruleId": "CKV_AWS_18",
                        "level": "warning",
                        "message": {"text": "Ensure S3 bucket has access logging enabled"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "s3.tf"},
                                    "region": {"startLine": 4},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }

    def fake_exec(self, args, cwd, timeout_seconds, allowed_exits=(0,)):
        # Checkov writes to results_sarif.sarif inside the output dir.
        out_idx = args.index("--output-file-path") + 1
        (Path(args[out_idx]) / "results_sarif.sarif").write_text(
            json.dumps(sarif_content), encoding="utf-8"
        )
        return _proc(code=0)

    monkeypatch.setattr(CheckovScanner, "_exec", fake_exec)
    findings = CheckovScanner().run(tmp_path, Config())
    assert findings
    assert all(f.category is Category.CONFIG_IAC for f in findings)
    assert findings[0].scanner == "checkov"


# --- Hadolint -------------------------------------------------------------


def test_hadolint_unavailable_emits_info(tmp_path, monkeypatch):
    _mock_available(monkeypatch, HadolintScanner, available=False)
    findings = HadolintScanner().run(tmp_path, Config())
    assert findings[0].severity is Severity.INFORMATIONAL


def test_hadolint_no_dockerfiles_returns_empty(tmp_path, monkeypatch):
    _mock_available(monkeypatch, HadolintScanner)
    findings = HadolintScanner().run(tmp_path, Config())
    assert findings[0].rule_id == "hadolint.no_dockerfiles"


def test_hadolint_parses_findings(tmp_path, monkeypatch):
    _mock_available(monkeypatch, HadolintScanner)
    (tmp_path / "Dockerfile").write_text("FROM python:3.11\nUSER root\n", encoding="utf-8")

    output = json.dumps(
        [
            {
                "file": "Dockerfile",
                "line": 2,
                "column": 1,
                "code": "DL3002",
                "level": "warning",
                "message": "Last USER should not be root",
            },
            {
                "file": "Dockerfile",
                "line": 1,
                "column": 1,
                "code": "DL3007",
                "level": "warning",
                "message": "Using latest tag",
            },
        ]
    )

    def fake_exec(self, args, cwd, timeout_seconds, allowed_exits=(0,)):
        return _proc(stdout=output, code=0)

    monkeypatch.setattr(HadolintScanner, "_exec", fake_exec)
    findings = HadolintScanner().run(tmp_path, Config())
    assert len(findings) == 2

    by_rule = {f.rule_id: f for f in findings}
    assert by_rule["hadolint.DL3002"].severity is Severity.HIGH  # USER root → HIGH
    assert by_rule["hadolint.DL3007"].severity is Severity.LOW  # latest tag → LOW


# --- OSV-Scanner ----------------------------------------------------------


def test_osv_unavailable_emits_info(tmp_path, monkeypatch):
    _mock_available(monkeypatch, OsvScanner, available=False)
    findings = OsvScanner().run(tmp_path, Config())
    assert findings[0].severity is Severity.INFORMATIONAL


def test_osv_parses_vulnerabilities(tmp_path, monkeypatch):
    _mock_available(monkeypatch, OsvScanner)
    captured = []

    payload = {
        "results": [
            {
                "source": {"path": "requirements.txt"},
                "packages": [
                    {
                        "package": {"name": "requests", "version": "2.20.0"},
                        "vulnerabilities": [
                            {
                                "id": "GHSA-x84v-xcm2-53pg",
                                "summary": "Cookie verification flaw",
                                "database_specific": {"severity": "HIGH"},
                            }
                        ],
                    }
                ],
            }
        ],
    }

    def fake_exec(self, args, cwd, timeout_seconds, allowed_exits=(0,)):
        captured.extend(args)
        return _proc(stdout=json.dumps(payload), code=1)

    monkeypatch.setattr(OsvScanner, "_exec", fake_exec)
    findings = OsvScanner().run(tmp_path, Config())
    assert len(findings) == 1
    f = findings[0]
    assert f.category is Category.DEPENDENCIES
    assert f.severity is Severity.HIGH
    assert "GHSA-x84v-xcm2-53pg" in f.message
    assert captured[:2] == ["scan", "source"]


# --- TruffleHog -----------------------------------------------------------


def test_trufflehog_unavailable_emits_info(tmp_path, monkeypatch):
    _mock_available(monkeypatch, TruffleHogScanner, available=False)
    findings = TruffleHogScanner().run(tmp_path, Config())
    assert findings[0].severity is Severity.INFORMATIONAL


def test_trufflehog_parses_verified_secret_as_critical(tmp_path, monkeypatch):
    _mock_available(monkeypatch, TruffleHogScanner)

    jsonl = "\n".join(
        [
            json.dumps(
                {
                    "DetectorName": "AWS",
                    "Verified": True,
                    "Redacted": "AKIA[REDACTED]",
                    "SourceMetadata": {
                        "Data": {
                            "Filesystem": {
                                "file": ".env",
                                "line": 4,
                            }
                        }
                    },
                }
            ),
            json.dumps(
                {
                    "DetectorName": "GenericApiKey",
                    "Verified": False,
                    "Redacted": "Bearer [REDACTED]",
                    "SourceMetadata": {
                        "Data": {
                            "Filesystem": {
                                "file": "config.py",
                                "line": 12,
                            }
                        }
                    },
                }
            ),
        ]
    )

    def fake_exec(self, args, cwd, timeout_seconds, allowed_exits=(0,)):
        return _proc(stdout=jsonl, code=0)

    monkeypatch.setattr(TruffleHogScanner, "_exec", fake_exec)
    findings = TruffleHogScanner().run(tmp_path, Config())
    assert len(findings) == 2

    by_detector = {f.rule_id: f for f in findings}
    assert by_detector["trufflehog.AWS"].severity is Severity.CRITICAL
    assert by_detector["trufflehog.GenericApiKey"].severity is Severity.HIGH
    # Category should always be SECRETS.
    assert all(f.category is Category.SECRETS for f in findings)


# --- Scorecard ------------------------------------------------------------


def test_scorecard_unavailable_emits_info(tmp_path, monkeypatch):
    _mock_available(monkeypatch, ScorecardScanner, available=False)
    findings = ScorecardScanner().run(tmp_path, Config())
    assert findings[0].severity is Severity.INFORMATIONAL


def test_scorecard_no_remote_emits_info(tmp_path, monkeypatch):
    _mock_available(monkeypatch, ScorecardScanner)
    monkeypatch.setattr(ScorecardScanner, "_infer_repo_url", lambda self, t: None)
    findings = ScorecardScanner().run(tmp_path, Config())
    assert findings[0].rule_id.endswith("no_remote")


def test_scorecard_score_to_severity():
    s = ScorecardScanner._score_to_severity
    assert s(None) is None
    assert s(10) is None  # passed cleanly
    assert s(-1) is Severity.INFORMATIONAL
    assert s(0) is Severity.HIGH
    assert s(2) is Severity.HIGH
    assert s(5) is Severity.MEDIUM
    assert s(8) is Severity.LOW


def test_scorecard_routes_security_policy_to_policy_docs(tmp_path, monkeypatch):
    _mock_available(monkeypatch, ScorecardScanner)
    monkeypatch.setattr(
        ScorecardScanner, "_infer_repo_url", lambda self, t: "https://github.com/o/r"
    )

    payload = {
        "checks": [
            {
                "name": "Security-Policy",
                "score": 0,
                "reason": "no security policy file",
                "documentation": {"url": "..."},
            },
            {
                "name": "Pinned-Dependencies",
                "score": 3,
                "reason": "unpinned deps",
                "documentation": {"url": "..."},
            },
        ],
    }

    def fake_exec(self, args, cwd, timeout_seconds, allowed_exits=(0,)):
        return _proc(stdout=json.dumps(payload), code=0)

    monkeypatch.setattr(ScorecardScanner, "_exec", fake_exec)
    findings = ScorecardScanner().run(tmp_path, Config())
    by_name = {f.rule_id: f for f in findings}
    assert by_name["scorecard.Security-Policy"].category is Category.POLICY_DOCS
    assert by_name["scorecard.Pinned-Dependencies"].category is Category.SUPPLY_CHAIN


def test_trufflehog_findings_exit_with_empty_stdout_fails_instead_of_reading_clean(
    tmp_path, monkeypatch
):
    # 183 is trufflehog asserting it found verified secrets.
    monkeypatch.setattr(
        TruffleHogScanner,
        "_exec",
        lambda self, args, cwd, timeout_seconds, allowed_exits=(0,): _proc(code=183),
    )
    scanner = TruffleHogScanner()
    scanner._resolved_command = ("trufflehog",)

    findings = scanner.run(tmp_path, Config())

    assert [f.rule_id for f in findings] == ["trufflehog.tool_error"]
    execution = classify_execution("trufflehog", findings)
    assert execution.outcome is ScannerOutcome.FAILED
    assert evaluate_coverage([execution], ["trufflehog"]).status is CoverageStatus.FAILED


def test_trufflehog_findings_exit_with_only_blank_lines_also_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(
        TruffleHogScanner,
        "_exec",
        lambda self, args, cwd, timeout_seconds, allowed_exits=(0,): _proc(
            stdout="\n  \n", code=183
        ),
    )
    scanner = TruffleHogScanner()
    scanner._resolved_command = ("trufflehog",)

    assert [f.rule_id for f in scanner.run(tmp_path, Config())] == ["trufflehog.tool_error"]


def test_trufflehog_clean_exit_with_empty_stdout_is_still_a_clean_scan(tmp_path, monkeypatch):
    monkeypatch.setattr(
        TruffleHogScanner,
        "_exec",
        lambda self, args, cwd, timeout_seconds, allowed_exits=(0,): _proc(code=0),
    )
    scanner = TruffleHogScanner()
    scanner._resolved_command = ("trufflehog",)

    findings = scanner.run(tmp_path, Config())

    assert findings == []
    assert classify_execution("trufflehog", findings).outcome is ScannerOutcome.COMPLETED
