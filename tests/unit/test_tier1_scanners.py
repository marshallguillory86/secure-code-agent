import json
from pathlib import Path
from subprocess import CompletedProcess

from secure_code_audit.config import Config
from secure_code_audit.findings import Category, Severity
from secure_code_audit.scanners.bandit_scanner import BanditScanner
from secure_code_audit.scanners.gitleaks_scanner import GitleaksScanner
from secure_code_audit.scanners.npm_audit_scanner import NpmAuditScanner
from secure_code_audit.scanners.semgrep_scanner import SemgrepScanner


def _proc(stdout="", stderr="", code=0):
    return CompletedProcess(args=["scanner"], returncode=code, stdout=stdout, stderr=stderr)


def _configured(scanner, command):
    scanner._resolved_command = (command,)
    return scanner


def test_bandit_parses_finding_and_control_failures(tmp_path, monkeypatch):
    payload = {
        "results": [
            {
                "test_id": "B608",
                "issue_text": "SQL expression",
                "filename": "app.py",
                "line_number": 8,
                "line_range": [8, 9],
                "code": "query = user",
                "issue_severity": "HIGH",
                "issue_confidence": "HIGH",
            }
        ]
    }
    scanner = _configured(BanditScanner(), "bandit")
    monkeypatch.setattr(
        scanner, "_exec", lambda *args, **kwargs: _proc(json.dumps(payload), code=1)
    )

    findings = scanner.run(tmp_path, Config())

    assert findings[0].rule_id == "B608"
    assert findings[0].severity is Severity.HIGH
    assert findings[0].line_end == 9

    monkeypatch.setattr(scanner, "_exec", lambda *args, **kwargs: _proc(stderr="slow", code=124))
    assert scanner.run(tmp_path, Config())[0].rule_id == "bandit.tool_timeout"
    monkeypatch.setattr(scanner, "_exec", lambda *args, **kwargs: _proc(stdout="bad json"))
    assert scanner.run(tmp_path, Config())[0].rule_id == "bandit.tool_error"


def test_bandit_requests_quiet_json_and_combines_excludes(tmp_path, monkeypatch):
    scanner = _configured(BanditScanner(), "bandit")
    captured = []

    def fake_exec(args, **kwargs):
        captured.extend(args)
        return _proc('{"results": []}')

    monkeypatch.setattr(scanner, "_exec", fake_exec)
    config = Config(exclude_patterns=["tests", "build", ".venv"])

    assert scanner.run(tmp_path, config) == []
    assert "--quiet" in captured
    assert captured.count("--exclude") == 1
    assert captured[captured.index("--exclude") + 1] == ",".join(
        [str(tmp_path / "tests"), str(tmp_path / "build"), str(tmp_path / ".venv")]
    )


def test_bandit_expands_directory_excludes_to_recursive_path_globs(tmp_path):
    excludes = BanditScanner._bandit_excludes(
        tmp_path, ("tests/", "build/", "**/__pycache__/", "**/*.min.js")
    )

    assert excludes == [
        str(tmp_path / "tests") + "/*",
        str(tmp_path / "build") + "/*",
        str(tmp_path / "**/__pycache__") + "/*",
        str(tmp_path / "**/*.min.js"),
    ]


def test_gitleaks_parses_redacted_secret_and_failures(tmp_path, monkeypatch):
    scanner = _configured(GitleaksScanner(), "gitleaks")
    payload = [
        {
            "RuleID": "aws-access-token",
            "Description": "AWS key",
            "File": ".env",
            "StartLine": 2,
            "EndLine": 2,
            "Match": "AKIA...REDACTED",
        }
    ]

    def fake_exec(self, args, cwd, timeout_seconds, allowed_exits=(0,)):
        report = Path(args[args.index("--report-path") + 1])
        report.write_text(json.dumps(payload), encoding="utf-8")
        return _proc(code=1)

    monkeypatch.setattr(GitleaksScanner, "_exec", fake_exec)
    findings = scanner.run(tmp_path, Config())
    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].category is Category.SECRETS
    assert "REDACTED" in findings[0].message

    monkeypatch.setattr(
        GitleaksScanner, "_exec", lambda *args, **kwargs: _proc(stderr="boom", code=2)
    )
    assert scanner.run(tmp_path, Config())[0].rule_id == "gitleaks.tool_error"


def test_gitleaks_invalid_json_is_parse_failure(tmp_path, monkeypatch):
    scanner = _configured(GitleaksScanner(), "gitleaks")

    def fake_exec(self, args, cwd, timeout_seconds, allowed_exits=(0,)):
        report = Path(args[args.index("--report-path") + 1])
        report.write_text("not json", encoding="utf-8")
        return _proc()

    monkeypatch.setattr(GitleaksScanner, "_exec", fake_exec)
    assert scanner.run(tmp_path, Config())[0].rule_id == "gitleaks.parse_error"


def test_npm_audit_discovers_projects_and_parses_direct_and_indirect(tmp_path, monkeypatch):
    project = tmp_path / "web"
    project.mkdir()
    (project / "package-lock.json").write_text("{}", encoding="utf-8")
    payload = {
        "vulnerabilities": {
            "direct": {
                "severity": "critical",
                "via": [{"source": 123, "title": "prototype pollution", "url": "https://x"}],
            },
            "indirect": {"severity": "moderate", "via": ["direct"]},
        }
    }
    scanner = _configured(NpmAuditScanner(), "npm")
    monkeypatch.setattr(
        scanner, "_exec", lambda *args, **kwargs: _proc(json.dumps(payload), code=1)
    )

    findings = scanner.run(tmp_path, Config())

    assert {finding.severity for finding in findings} == {Severity.CRITICAL, Severity.MEDIUM}
    assert all(finding.file_path == project / "package-lock.json" for finding in findings)


def test_npm_audit_reports_timeout_error_and_parse_failure(tmp_path, monkeypatch):
    (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
    scanner = _configured(NpmAuditScanner(), "npm")

    monkeypatch.setattr(scanner, "_exec", lambda *args, **kwargs: _proc(code=124))
    assert scanner.run(tmp_path, Config())[0].rule_id == "npm_audit.tool_timeout"
    monkeypatch.setattr(scanner, "_exec", lambda *args, **kwargs: _proc(stderr="boom", code=2))
    assert scanner.run(tmp_path, Config())[0].rule_id == "npm_audit.tool_error"
    monkeypatch.setattr(scanner, "_exec", lambda *args, **kwargs: _proc(stdout="bad"))
    assert scanner.run(tmp_path, Config())[0].rule_id == "npm_audit.parse_error"


def test_semgrep_parses_sarif_and_reports_invalid_output(tmp_path, monkeypatch):
    payload = {
        "runs": [
            {
                "tool": {
                    "driver": {
                        "rules": [
                            {
                                "id": "python.lang.security.audit.exec-detected",
                                "defaultConfiguration": {"level": "error"},
                                "properties": {"cwe": ["CWE-95"]},
                            }
                        ]
                    }
                },
                "results": [
                    {
                        "ruleId": "python.lang.security.audit.exec-detected",
                        "level": "error",
                        "message": {"text": "exec detected"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "app.py"},
                                    "region": {
                                        "startLine": 3,
                                        "endLine": 3,
                                        "snippet": {"text": "exec(x)"},
                                    },
                                }
                            }
                        ],
                    }
                ],
            }
        ]
    }
    scanner = _configured(SemgrepScanner(), "semgrep")

    def fake_exec(self, args, cwd, timeout_seconds, allowed_exits=(0,)):
        output = Path(args[args.index("--output") + 1])
        output.write_text(json.dumps(payload), encoding="utf-8")
        return _proc(code=1)

    monkeypatch.setattr(SemgrepScanner, "_exec", fake_exec)
    findings = scanner.run(tmp_path, Config())
    assert findings[0].canonical_cwe == "CWE-95"
    assert findings[0].severity is Severity.HIGH

    def invalid_exec(self, args, cwd, timeout_seconds, allowed_exits=(0,)):
        output = Path(args[args.index("--output") + 1])
        output.write_text("bad", encoding="utf-8")
        return _proc()

    monkeypatch.setattr(SemgrepScanner, "_exec", invalid_exec)
    assert scanner.run(tmp_path, Config())[0].rule_id == "semgrep.tool_error"
