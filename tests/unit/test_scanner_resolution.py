import os
import subprocess
import sys

from secure_code_audit.config import Config, ScannerConfig
from secure_code_audit.scanners.bandit_scanner import BanditScanner


def test_explicit_relative_command_resolves_from_target(tmp_path):
    executable = tmp_path / ".tools" / "bandit"
    executable.parent.mkdir()
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o755)
    config = Config(scanners={"bandit": ScannerConfig(command=[".tools/bandit"])})

    scanner = BanditScanner()
    scanner.configure(tmp_path, config)

    assert scanner.command == (str(executable.resolve()),)
    assert scanner.is_available()


def test_non_executable_configured_command_is_unavailable(tmp_path):
    executable = tmp_path / "bandit"
    executable.write_text("not executable", encoding="utf-8")
    executable.chmod(0o644)
    config = Config(scanners={"bandit": ScannerConfig(command=[str(executable)])})

    scanner = BanditScanner()
    scanner.configure(tmp_path, config)

    assert scanner.command == ()
    assert not scanner.is_available()


def test_python_module_fallback_uses_active_interpreter(tmp_path, monkeypatch):
    monkeypatch.setattr("secure_code_audit.scanners.base.shutil.which", lambda _name: None)
    monkeypatch.setattr(
        "secure_code_audit.scanners.base.importlib.util.find_spec", lambda _name: object()
    )

    scanner = BanditScanner()
    scanner.configure(tmp_path, Config())

    assert scanner.command == (sys.executable, "-m", "bandit")
    assert os.path.isabs(scanner.command[0])


def test_named_configured_command_uses_path_and_reports_version(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "secure_code_audit.scanners.base.shutil.which",
        lambda name: "/tools/bandit" if name == "custom-bandit" else None,
    )
    monkeypatch.setattr(
        "secure_code_audit.scanners.base.subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args=args[0], returncode=0, stdout="bandit 1.9.4\n", stderr=""
        ),
    )
    config = Config(scanners={"bandit": ScannerConfig(command=["custom-bandit", "wrapper"])})
    scanner = BanditScanner()
    scanner.configure(tmp_path, config)

    assert scanner.command == ("/tools/bandit", "wrapper")
    assert scanner.binary_version() == "bandit 1.9.4"


def test_version_and_exec_failures_are_contained(tmp_path, monkeypatch):
    scanner = BanditScanner()
    scanner._resolved_command = ("bandit",)
    monkeypatch.setattr(
        "secure_code_audit.scanners.base.subprocess.run",
        lambda *args, **kwargs: (_ for _ in ()).throw(subprocess.TimeoutExpired("bandit", 1)),
    )
    assert scanner.binary_version() is None

    result = scanner._exec(["bandit"], tmp_path, 1)
    assert result.returncode == 124
    assert "timeout" in result.stderr


def test_sanitized_environment_keeps_allowlist(monkeypatch):
    monkeypatch.setenv("PATH", "/tools")
    monkeypatch.setenv("LANG", "C")
    monkeypatch.setenv("SECRET_TOKEN", "do-not-forward")

    environment = BanditScanner._sanitized_env()

    assert environment["PATH"] == "/tools"
    assert environment["LANG"] == "C"
    assert "SECRET_TOKEN" not in environment
