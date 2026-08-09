import json
from subprocess import CompletedProcess

from secure_code_audit.config import Config, ScannerConfig
from secure_code_audit.findings import Severity
from secure_code_audit.scanners.pip_audit_scanner import PipAuditScanner


def _proc(stdout: str = "", stderr: str = "", code: int = 0) -> CompletedProcess:
    return CompletedProcess(args=["pip-audit"], returncode=code, stdout=stdout, stderr=stderr)


def _config(**kwargs) -> Config:
    return Config(scanners={"pip_audit": ScannerConfig(**kwargs)})


def _scanner() -> PipAuditScanner:
    scanner = PipAuditScanner()
    scanner._resolved_command = ("pip-audit",)
    return scanner


def test_auto_mode_audits_pyproject_project(tmp_path, monkeypatch):
    (tmp_path / "pyproject.toml").write_text("[project]\nname='demo'\n", encoding="utf-8")
    captured = []

    def fake_exec(self, args, cwd, timeout_seconds, allowed_exits=(0,)):
        captured.append(args)
        return _proc(stdout=json.dumps({"dependencies": []}))

    monkeypatch.setattr(PipAuditScanner, "_exec", fake_exec)
    findings = _scanner().run(tmp_path, _config())

    assert findings == []
    assert captured[0][1:3] == [str(tmp_path), "--format=json"]


def test_locked_mode_passes_locked_before_project(tmp_path, monkeypatch):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[project]\nname='demo'\n", encoding="utf-8")
    captured = []

    def fake_exec(self, args, cwd, timeout_seconds, allowed_exits=(0,)):
        captured.append(args)
        return _proc(stdout=json.dumps({"dependencies": []}))

    monkeypatch.setattr(PipAuditScanner, "_exec", fake_exec)
    _scanner().run(tmp_path, _config(mode="locked"))

    assert captured[0][1:4] == ["--locked", str(tmp_path), "--format=json"]


def test_auto_mode_prefers_requirements_in_same_project(tmp_path, monkeypatch):
    (tmp_path / "pyproject.toml").write_text("[project]\nname='demo'\n", encoding="utf-8")
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("demo==1.0\n", encoding="utf-8")
    captured = []

    def fake_exec(self, args, cwd, timeout_seconds, allowed_exits=(0,)):
        captured.append(args)
        return _proc(stdout=json.dumps({"dependencies": []}))

    monkeypatch.setattr(PipAuditScanner, "_exec", fake_exec)
    _scanner().run(tmp_path, _config())

    assert len(captured) == 1
    assert captured[0][1:4] == ["-r", str(requirements), "--format=json"]


def test_invalid_json_is_visible_failure(tmp_path, monkeypatch):
    (tmp_path / "pyproject.toml").write_text("[project]\nname='demo'\n", encoding="utf-8")
    monkeypatch.setattr(
        PipAuditScanner,
        "_exec",
        lambda *args, **kwargs: _proc(stdout="not json"),
    )

    findings = _scanner().run(tmp_path, _config())

    assert findings[0].rule_id == "pip_audit.parse_error"
    assert findings[0].severity is Severity.INFORMATIONAL


def test_no_dependency_input_is_not_applicable(tmp_path, monkeypatch):
    findings = _scanner().run(tmp_path, _config())

    assert findings[0].rule_id == "pip_audit.no_dependency_input"


def test_unavailable_invalid_mode_and_missing_input_are_visible(tmp_path):
    unavailable_scanner = PipAuditScanner()
    unavailable_scanner._resolved_command = ()
    unavailable = unavailable_scanner.run(tmp_path, _config())
    invalid_mode = _scanner().run(tmp_path, _config(mode="mystery"))
    missing = _scanner().run(tmp_path, _config(mode="project", inputs=["missing.toml"]))

    assert unavailable[0].rule_id == "pip_audit.tool_unavailable"
    assert invalid_mode[0].rule_id == "pip_audit.tool_error"
    assert missing[0].rule_id == "pip_audit.tool_error"


def test_environment_mode_and_explicit_input_validation(tmp_path, monkeypatch):
    captured = []

    def fake_exec(self, args, cwd, timeout_seconds, allowed_exits=(0,)):
        captured.append(args)
        return _proc(stdout=json.dumps({"dependencies": []}))

    monkeypatch.setattr(PipAuditScanner, "_exec", fake_exec)
    findings = _scanner().run(tmp_path, _config(mode="environment"))
    invalid = _scanner().run(tmp_path, _config(mode="environment", inputs=[str(tmp_path)]))

    assert findings == []
    assert captured[0] == ["pip-audit", "--format=json"]
    assert invalid[0].rule_id == "pip_audit.tool_error"


def test_requirements_mode_discovers_nested_inputs_and_excludes_venv(tmp_path, monkeypatch):
    app = tmp_path / "app"
    app.mkdir()
    requirement = app / "requirements-dev.txt"
    requirement.write_text("demo==1\n", encoding="utf-8")
    excluded = tmp_path / ".venv" / "requirements.txt"
    excluded.parent.mkdir()
    excluded.write_text("ignore==1\n", encoding="utf-8")
    captured = []

    def fake_exec(self, args, cwd, timeout_seconds, allowed_exits=(0,)):
        captured.append(args)
        return _proc(stdout="[]")

    monkeypatch.setattr(PipAuditScanner, "_exec", fake_exec)
    findings = _scanner().run(tmp_path, _config(mode="requirements"))

    assert findings == []
    assert len(captured) == 1
    assert str(requirement) in captured[0]


def test_subprocess_failure_modes_and_vulnerability_parsing(tmp_path, monkeypatch):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("[project]\nname='demo'\n", encoding="utf-8")
    scanner = _scanner()

    monkeypatch.setattr(scanner, "_exec", lambda *args, **kwargs: _proc(code=124))
    assert scanner.run(tmp_path, _config())[0].rule_id == "pip_audit.tool_timeout"
    monkeypatch.setattr(
        scanner, "_exec", lambda *args, **kwargs: _proc(stderr="resolver failed", code=2)
    )
    assert scanner.run(tmp_path, _config())[0].rule_id == "pip_audit.tool_error"
    monkeypatch.setattr(scanner, "_exec", lambda *args, **kwargs: _proc())
    assert scanner.run(tmp_path, _config())[0].rule_id == "pip_audit.tool_error"

    payload = [
        {
            "name": "demo",
            "version": "1.0",
            "vulns": [
                {
                    "id": "GHSA-demo",
                    "description": "vulnerable",
                    "fix_versions": ["1.1"],
                }
            ],
        }
    ]
    monkeypatch.setattr(
        scanner, "_exec", lambda *args, **kwargs: _proc(json.dumps(payload), code=1)
    )
    finding = scanner.run(tmp_path, _config())[0]
    assert finding.rule_id == "pip_audit.GHSA-demo"
    assert "Fix in: 1.1" in finding.message


def test_invalid_json_root_is_parse_failure(tmp_path, monkeypatch):
    (tmp_path / "pyproject.toml").write_text("[project]\nname='demo'\n", encoding="utf-8")
    scanner = _scanner()
    monkeypatch.setattr(scanner, "_exec", lambda *args, **kwargs: _proc("123"))

    assert scanner.run(tmp_path, _config())[0].rule_id == "pip_audit.parse_error"
