import json
from pathlib import Path
from subprocess import CompletedProcess

from secure_code_audit.config import Config, ScannerConfig
from secure_code_audit.findings import Category, Severity
from secure_code_audit.scanner_status import (
    CoverageStatus,
    ScannerOutcome,
    classify_execution,
    evaluate_coverage,
)
from secure_code_audit.scanners import semgrep_scanner
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


def test_gitleaks_findings_exit_with_empty_report_fails_instead_of_reading_clean(
    tmp_path, monkeypatch
):
    # Exit 1 is gitleaks asserting it found secrets. An empty report then means
    # we have nothing to show for it — recording a clean scan would discard the
    # scanner's own signal in the highest-weighted category.
    def fake_exec(self, args, cwd, timeout_seconds, allowed_exits=(0,)):
        Path(args[args.index("--report-path") + 1]).write_text("", encoding="utf-8")
        return _proc(code=1)

    monkeypatch.setattr(GitleaksScanner, "_exec", fake_exec)
    findings = _configured(GitleaksScanner(), "gitleaks").run(tmp_path, Config())

    assert [f.rule_id for f in findings] == ["gitleaks.tool_error"]
    execution = classify_execution("gitleaks", findings)
    assert execution.outcome is ScannerOutcome.FAILED
    assert evaluate_coverage([execution], ["gitleaks"]).status is CoverageStatus.FAILED


def test_gitleaks_findings_exit_with_empty_array_report_also_fails(tmp_path, monkeypatch):
    def fake_exec(self, args, cwd, timeout_seconds, allowed_exits=(0,)):
        Path(args[args.index("--report-path") + 1]).write_text("[]", encoding="utf-8")
        return _proc(code=1)

    monkeypatch.setattr(GitleaksScanner, "_exec", fake_exec)
    findings = _configured(GitleaksScanner(), "gitleaks").run(tmp_path, Config())

    assert [f.rule_id for f in findings] == ["gitleaks.tool_error"]


def test_gitleaks_clean_exit_with_empty_report_is_still_a_clean_scan(tmp_path, monkeypatch):
    def fake_exec(self, args, cwd, timeout_seconds, allowed_exits=(0,)):
        Path(args[args.index("--report-path") + 1]).write_text("", encoding="utf-8")
        return _proc(code=0)

    monkeypatch.setattr(GitleaksScanner, "_exec", fake_exec)
    findings = _configured(GitleaksScanner(), "gitleaks").run(tmp_path, Config())

    assert findings == []
    assert classify_execution("gitleaks", findings).outcome is ScannerOutcome.COMPLETED


def test_gitleaks_non_array_report_is_a_parse_error(tmp_path, monkeypatch):
    def fake_exec(self, args, cwd, timeout_seconds, allowed_exits=(0,)):
        Path(args[args.index("--report-path") + 1]).write_text('{"oops": 1}', encoding="utf-8")
        return _proc(code=0)

    monkeypatch.setattr(GitleaksScanner, "_exec", fake_exec)
    findings = _configured(GitleaksScanner(), "gitleaks").run(tmp_path, Config())

    assert [f.rule_id for f in findings] == ["gitleaks.parse_error"]


def test_semgrep_offline_uses_the_packaged_ruleset_not_the_registry(tmp_path, monkeypatch):
    # `p/security-audit` reads as bundled but is a Registry ruleset fetched over
    # the network, so offline silently was not offline.
    captured: dict = {}

    def fake_exec(self, args, cwd, timeout_seconds, allowed_exits=(0,)):
        captured["args"] = args
        Path(args[args.index("--output") + 1]).write_text(
            json.dumps({"runs": [{"tool": {"driver": {"rules": []}}, "results": []}]}),
            encoding="utf-8",
        )
        return _proc()

    monkeypatch.setattr(SemgrepScanner, "_exec", fake_exec)
    config = Config()
    config.scanners["semgrep"] = ScannerConfig(online=False)
    _configured(SemgrepScanner(), "semgrep").run(tmp_path, config)

    config_arg = captured["args"][captured["args"].index("--config") + 1]
    assert config_arg.endswith("semgrep-offline.yaml")
    assert not config_arg.startswith("p/")
    # Rule ids would otherwise be prefixed with the config file's path,
    # varying by install location and destabilizing baseline fingerprints.
    assert "--no-rewrite-rule-ids" in captured["args"]


def test_semgrep_offline_fails_closed_when_the_ruleset_is_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(semgrep_scanner, "offline_ruleset_path", lambda: None)
    config = Config()
    config.scanners["semgrep"] = ScannerConfig(online=False)

    findings = _configured(SemgrepScanner(), "semgrep").run(tmp_path, config)

    assert [f.rule_id for f in findings] == ["semgrep.tool_error"]
    assert "packaged ruleset" in findings[0].message
    assert classify_execution("semgrep", findings).outcome is ScannerOutcome.FAILED


def test_semgrep_recovers_cwe_from_tags_as_well_as_properties():
    # Semgrep folds metadata.cwe into properties.tags, so reading only
    # properties.cwe left every semgrep finding without a CWE.
    from secure_code_audit.scanners.semgrep_scanner import _cwe_from_rule

    assert _cwe_from_rule({"properties": {"tags": ["CWE-78", "security"]}}) == "CWE-78"
    assert _cwe_from_rule({"properties": {"cwe": ["CWE-89: SQL Injection"]}}) == "CWE-89"
    assert _cwe_from_rule({"properties": {"cwe": "CWE-22"}}) == "CWE-22"
    assert _cwe_from_rule({"properties": {"tags": ["security"]}}) is None
    assert _cwe_from_rule({}) is None


def test_packaged_offline_ruleset_is_present_and_well_formed():
    import yaml

    path = semgrep_scanner.offline_ruleset_path()
    assert path is not None, "the offline ruleset must ship with the package"
    rules = yaml.safe_load(path.read_text(encoding="utf-8"))["rules"]
    assert rules
    for rule in rules:
        assert rule["id"].startswith("sca.offline.")
        assert rule["metadata"]["cwe"].startswith("CWE-")
        assert rule["severity"] in {"ERROR", "WARNING", "INFO"}
