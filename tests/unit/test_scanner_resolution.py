import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from secure_code_audit.config import Config, ScannerConfig, target_executables_allowed
from secure_code_audit.config import load as config_load
from secure_code_audit.scanners.bandit_scanner import BanditScanner


def test_explicit_relative_command_resolves_from_target(tmp_path):
    executable = tmp_path / ".tools" / "bandit"
    executable.parent.mkdir()
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o755)
    # A relative command still resolves from the target — but only once the
    # operator has vouched for the tree. Resolution mechanics and the trust
    # boundary are separate properties; this one tests the mechanics.
    config = Config(
        scanners={"bandit": ScannerConfig(command=[".tools/bandit"])},
        trust_target_config=True,
    )

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


def _tree_with_executable(tmp_path):
    tool = tmp_path / "pwn.sh"
    tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    tool.chmod(0o755)
    return tool


def _config_naming(tmp_path, command, *, source: Path | None, trust: bool = False):
    cfg = Config()
    cfg.scanners["bandit"] = ScannerConfig(command=command)
    cfg.source_path = source
    cfg.trust_target_config = trust
    return cfg


def test_config_inside_the_tree_cannot_choose_an_executable_from_the_tree(tmp_path):
    # threat-model T1: repository content must not select what the host runs.
    _tree_with_executable(tmp_path)
    cfg = _config_naming(tmp_path, ["./pwn.sh"], source=tmp_path / "secure-code-agent.json")

    scanner = BanditScanner()
    scanner.configure(tmp_path, cfg)

    assert scanner.command == ()
    assert not scanner.is_available()


def test_an_operator_config_outside_the_tree_keeps_the_tree_local_workflow(tmp_path):
    # The documented `.audit-tools/bin/python` case: the operator authored a
    # config they keep outside the audited tree, so their choice stands.
    tool = _tree_with_executable(tmp_path)
    outside = tmp_path.parent / "operator-config.json"
    cfg = _config_naming(tmp_path, [str(tool)], source=outside)

    scanner = BanditScanner()
    scanner.configure(tmp_path, cfg)

    assert scanner.command == (str(tool.resolve()),)


def test_trust_target_config_is_an_explicit_operator_opt_in(tmp_path):
    _tree_with_executable(tmp_path)
    cfg = _config_naming(
        tmp_path, ["./pwn.sh"], source=tmp_path / "secure-code-agent.json", trust=True
    )

    scanner = BanditScanner()
    scanner.configure(tmp_path, cfg)

    assert scanner.command  # the operator asserted the tree is theirs


def test_a_config_file_cannot_grant_itself_trust(tmp_path):
    # If `trust_target_config` were readable from the config, repository
    # content would hand itself the trust the flag exists to withhold. The
    # loader rejects the key rather than ignoring it, so an operator who tries
    # is told, instead of believing they enabled something.
    payload = {"version": 1, "trust_target_config": True, "scanners": {}}
    path = tmp_path / "secure-code-agent.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="unknown configuration key"):
        config_load(path)

    assert Config().trust_target_config is False


def test_defaults_never_allow_executables_from_the_tree(tmp_path):
    assert target_executables_allowed(Config(), tmp_path) is False


def test_the_floor_and_optional_sets_are_disjoint_and_complete():
    from secure_code_audit.scanners import SCANNERS, floor

    declared = set(floor.FLOOR_NAMES) | set(floor.OPTIONAL_NAMES)
    assert not set(floor.FLOOR_NAMES) & set(floor.OPTIONAL_NAMES)
    # Every registered scanner has a stated position. A tool nobody decided
    # about is the gap this floor exists to remove.
    assert declared == set(SCANNERS), f"undeclared: {set(SCANNERS) ^ declared}"


def test_every_declared_tool_records_a_licence_and_a_reason():
    from secure_code_audit.scanners import floor

    for policy in (*floor.FLOOR, *floor.OPTIONAL):
        assert policy.licence, f"{policy.name} has no licence recorded"
        assert policy.rationale, f"{policy.name} has no rationale"
    for policy in floor.OPTIONAL:
        # "We left it out" and "we never considered it" are different
        # statements, and only one of them is useful.
        assert policy.optional_because, f"{policy.name} is optional with no reason"


def test_optional_tools_are_off_by_default_and_floor_tools_are_on():
    from secure_code_audit.scanners import floor

    assert all(floor.default_enabled(n) for n in floor.FLOOR_NAMES)
    assert not any(floor.default_enabled(n) for n in floor.OPTIONAL_NAMES)


def test_agpl_tools_are_never_in_the_floor():
    # D6 criterion 2: AGPL stays opt-in so a hosted-service source-offer
    # obligation is never imposed on an adopter by default.
    from secure_code_audit.scanners import floor

    for policy in floor.FLOOR:
        assert "AGPL" not in policy.licence, f"{policy.name} is AGPL and in the floor"


def test_the_floor_token_expands_and_deduplicates():
    from secure_code_audit.scanners import floor

    assert floor.expand_required(["floor"]) == list(floor.FLOOR_NAMES)
    assert floor.expand_required(["bandit", "floor", "bandit"])[0] == "bandit"
    assert len(floor.expand_required(["floor", "floor"])) == len(floor.FLOOR_NAMES)


def test_a_tool_with_nothing_to_scan_is_not_a_coverage_gap():
    from secure_code_audit.scanners import floor

    # A pure-Python tree: the Dockerfile/IaC tools have nothing to read.
    python_only = ({".py"}, {"main.py"})
    assert floor.applies_to_repository("bandit", *python_only)
    assert not floor.applies_to_repository("trivy", *python_only)
    # Secrets and supply chain are not tied to a language.
    assert floor.applies_to_repository("gitleaks", *python_only)
    assert floor.applies_to_repository("scorecard", *python_only)


def test_a_failed_version_probe_is_not_reported_as_a_version(tmp_path, monkeypatch):
    # Scorecard has no --version flag. The probe's stderr was landing in the
    # version column of a report that otherwise claimed the scanner ran fine.
    monkeypatch.setattr(
        "secure_code_audit.scanners.base.subprocess.run",
        lambda *a, **k: subprocess.CompletedProcess(
            args=a[0], returncode=1, stdout="", stderr="Error: unknown flag: --version"
        ),
    )
    scanner = BanditScanner()
    scanner._resolved_command = ("bandit",)

    assert scanner.binary_version() is None


def test_an_adapter_supplies_its_own_timeout_when_config_is_silent(tmp_path):
    from secure_code_audit.scanners.scorecard_scanner import ScorecardScanner

    scorecard = ScorecardScanner()
    bandit = BanditScanner()

    # Scorecard queries a remote API and legitimately needs longer; an
    # operator should not have to learn that from a timeout.
    assert scorecard.cfg(Config()).timeout_seconds == scorecard.default_timeout_seconds
    assert scorecard.cfg(Config()).timeout_seconds > bandit.cfg(Config()).timeout_seconds


def test_a_configured_timeout_still_wins_over_the_adapter_default():
    from secure_code_audit.scanners.scorecard_scanner import ScorecardScanner

    config = Config(scanners={"scorecard": ScannerConfig(timeout_seconds=30)})

    assert ScorecardScanner().cfg(config).timeout_seconds == 30
