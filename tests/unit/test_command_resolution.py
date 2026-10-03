"""`CommandResolution` — which program will run, and whether it may.

Tested on a minimal probe class carrying only what the mixin expects from
`Scanner` (`name`, `binary`, `cfg`), so the resolution rules are exercised
without any concrete adapter in the way. Real executables are written to
`tmp_path`; only PATH lookup and the `--version` probe are patched.
"""

from __future__ import annotations

import subprocess
import sys

from secure_code_audit.config import Config, ScannerConfig
from secure_code_audit.scanners import _resolution
from secure_code_audit.scanners._resolution import CommandResolution


class _Probe(CommandResolution):
    name = "probe"
    binary = "probe-bin"

    def cfg(self, config):
        return config.scanners.get(self.name, ScannerConfig())


class _NoBinary(_Probe):
    binary = ""


class _WithModule(_Probe):
    python_module = "probe_mod"


def _exe(path, body="#!/bin/sh\nexit 0\n", mode=0o755):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    path.chmod(mode)
    return path


def _which(mapping):
    return lambda name: mapping.get(name)


def _trusted(**kw):
    return Config(trust_target_config=True, **kw)


# --- command resolution -------------------------------------------------


def test_command_before_configure_falls_back_to_path(monkeypatch):
    """An unconfigured scanner still resolves its binary from PATH."""
    monkeypatch.setattr(_resolution.shutil, "which", _which({"probe-bin": "/usr/bin/probe-bin"}))

    assert _Probe().command == ("/usr/bin/probe-bin",)


def test_command_before_configure_is_empty_when_not_on_path(monkeypatch):
    monkeypatch.setattr(_resolution.shutil, "which", _which({}))

    probe = _Probe()

    assert probe.command == ()
    assert not probe.is_available()


def test_scanner_with_no_binary_name_never_asks_path(monkeypatch):
    """An empty `binary` must not be looked up (which('') is meaningless)."""
    calls = []
    monkeypatch.setattr(_resolution.shutil, "which", lambda n: calls.append(n))

    probe = _NoBinary()
    probe.configure(__import__("pathlib").Path("/nonexistent-target"), Config())

    assert probe.command == ()
    assert calls == []


def test_configure_resolves_once_and_command_reports_that_result(tmp_path, monkeypatch):
    """After configure, `command` is the resolved tuple, not a fresh PATH lookup.

    Prevents probing and execution using different tools: PATH is changed
    after configure and the answer must not move.
    """
    outside = tmp_path / "outside"
    tool = _exe(outside / "probe-bin")
    target = tmp_path / "repo"
    target.mkdir()
    monkeypatch.setattr(_resolution.shutil, "which", _which({"probe-bin": str(tool)}))
    probe = _Probe()
    probe.configure(target, Config())

    monkeypatch.setattr(_resolution.shutil, "which", _which({"probe-bin": "/somewhere/else"}))

    assert probe.command == (str(tool),)


def test_python_module_fallback_when_binary_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(_resolution.shutil, "which", _which({}))
    monkeypatch.setattr(_resolution.importlib.util, "find_spec", lambda n: object())
    probe = _WithModule()

    probe.configure(tmp_path, Config())

    assert probe.command == (sys.executable, "-m", "probe_mod")


def test_python_module_fallback_not_used_when_module_absent(tmp_path, monkeypatch):
    monkeypatch.setattr(_resolution.shutil, "which", _which({}))
    monkeypatch.setattr(_resolution.importlib.util, "find_spec", lambda n: None)
    probe = _WithModule()

    probe.configure(tmp_path, Config())

    assert probe.command == ()


def test_binary_on_path_beats_the_python_module_fallback(tmp_path, monkeypatch):
    outside = tmp_path / "outside"
    tool = _exe(outside / "probe-bin")
    target = tmp_path / "repo"
    target.mkdir()
    monkeypatch.setattr(_resolution.shutil, "which", _which({"probe-bin": str(tool)}))
    monkeypatch.setattr(_resolution.importlib.util, "find_spec", lambda n: object())
    probe = _WithModule()

    probe.configure(target, Config())

    assert probe.command == (str(tool),)


def test_configured_absolute_command_keeps_its_arguments(tmp_path):
    tool = _exe(tmp_path / "outside" / "custom")
    target = tmp_path / "repo"
    target.mkdir()
    # Config lives outside the tree, so it is trusted without a flag.
    config = Config(scanners={"probe": ScannerConfig(command=[str(tool), "--flag", "v"])})
    probe = _Probe()

    probe.configure(target, config)

    assert probe.command == (str(tool.resolve()), "--flag", "v")


def test_configured_nonexecutable_command_is_unavailable(tmp_path):
    tool = _exe(tmp_path / "outside" / "custom", mode=0o644)
    config = Config(scanners={"probe": ScannerConfig(command=[str(tool)])})
    probe = _Probe()

    probe.configure(tmp_path / "repo", config)

    assert probe.command == ()


def test_configured_command_naming_a_directory_is_unavailable(tmp_path):
    directory = tmp_path / "outside" / "adir"
    directory.mkdir(parents=True)
    config = Config(scanners={"probe": ScannerConfig(command=[str(directory)])})
    probe = _Probe()

    probe.configure(tmp_path / "repo", config)

    assert probe.command == ()


def test_configured_bare_name_missing_from_path_is_unavailable(tmp_path, monkeypatch):
    """A configured name that is not on PATH must not fall back to the default binary."""
    monkeypatch.setattr(_resolution.shutil, "which", _which({"probe-bin": "/usr/bin/probe-bin"}))
    config = Config(scanners={"probe": ScannerConfig(command=["custom-name"])})
    probe = _Probe()

    probe.configure(tmp_path, config)

    assert probe.command == ()


def test_relative_command_resolves_against_the_target_when_trusted(tmp_path):
    tool = _exe(tmp_path / ".tools" / "probe")
    config = _trusted(scanners={"probe": ScannerConfig(command=[".tools/probe"])})
    probe = _Probe()

    probe.configure(tmp_path, config)

    assert probe.command == (str(tool.resolve()),)


def test_relative_command_for_a_file_target_resolves_against_its_parent(tmp_path):
    """The containment root of a file target is its directory.

    Prevents `app.py/.tools/probe` -- a path that cannot exist -- silently
    yielding "no command". The resolved tool is the one beside the file.
    """
    tool = _exe(tmp_path / ".tools" / "probe")
    target = tmp_path / "app.py"
    target.write_text("x = 1\n", encoding="utf-8")
    config = _trusted(scanners={"probe": ScannerConfig(command=[".tools/probe"])})
    probe = _Probe()

    probe.configure(target, config)

    assert probe.command == (str(tool.resolve()),)


# --- containment --------------------------------------------------------


def test_path_binary_inside_the_audited_tree_is_refused(tmp_path, monkeypatch):
    """The containment check applies to PATH resolution too, not only explicit paths.

    Prevents a tree-local directory on PATH ('.' or a venv bin) letting the
    audited repository choose what the host executes.
    """
    tool = _exe(tmp_path / "bin" / "probe-bin")
    monkeypatch.setattr(_resolution.shutil, "which", _which({"probe-bin": str(tool)}))
    probe = _Probe()

    probe.configure(tmp_path, Config())

    assert probe.command == ()
    assert not probe.is_available()


def test_path_binary_inside_the_tree_is_allowed_once_trusted(tmp_path, monkeypatch):
    """Companion to the refusal above: the same layout passes when the operator vouches.

    Without this the refusal test could pass because resolution is broken.
    """
    tool = _exe(tmp_path / "bin" / "probe-bin")
    monkeypatch.setattr(_resolution.shutil, "which", _which({"probe-bin": str(tool)}))
    probe = _Probe()

    probe.configure(tmp_path, _trusted())

    assert probe.command == (str(tool),)


def test_file_target_containment_uses_the_parent_directory(tmp_path, monkeypatch):
    """A tool beside a single-file target is still inside the tree.

    Prevents the inverted check where nothing lives beneath a regular file, so
    everything read as "allowed".
    """
    tool = _exe(tmp_path / "probe-bin")
    target = tmp_path / "app.py"
    target.write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setattr(_resolution.shutil, "which", _which({"probe-bin": str(tool)}))
    probe = _Probe()

    probe.configure(target, Config())

    assert probe.command == ()


def test_untrusted_in_tree_config_cannot_choose_the_command(tmp_path, monkeypatch):
    """A config from the audited tree is ignored, and says so.

    The default binary must be used instead of the config's choice, and
    `ignored_command` must be set so the report can mention it.
    """
    outside = tmp_path / "outside"
    default_tool = _exe(outside / "probe-bin")
    chosen = _exe(outside / "chosen")
    target = tmp_path / "repo"
    target.mkdir()
    monkeypatch.setattr(_resolution.shutil, "which", _which({"probe-bin": str(default_tool)}))
    config = Config(scanners={"probe": ScannerConfig(command=[str(chosen)])})
    config.source_path = target / "secure-code-agent.json"
    probe = _Probe()

    probe.configure(target, config)

    assert probe.ignored_command is True
    assert probe.command == (str(default_tool),)


def test_trusted_in_tree_config_choice_is_honoured_and_not_flagged(tmp_path):
    chosen = _exe(tmp_path / "outside" / "chosen")
    target = tmp_path / "repo"
    target.mkdir()
    config = Config(scanners={"probe": ScannerConfig(command=[str(chosen)])})
    config.source_path = target / "secure-code-agent.json"
    config.trust_target_config = True
    probe = _Probe()

    probe.configure(target, config)

    assert probe.ignored_command is False
    assert probe.command == (str(chosen.resolve()),)


def test_no_configured_command_is_never_reported_as_ignored(tmp_path, monkeypatch):
    monkeypatch.setattr(_resolution.shutil, "which", _which({}))
    probe = _Probe()

    probe.configure(tmp_path, Config())

    assert probe.ignored_command is False


# --- version probe ------------------------------------------------------


def _with_version_output(monkeypatch, *, stdout="", stderr="", returncode=0):
    seen = []

    def fake_run(args, **kwargs):
        seen.append((args, kwargs))
        return subprocess.CompletedProcess(args, returncode, stdout=stdout, stderr=stderr)

    monkeypatch.setattr(_resolution.subprocess, "run", fake_run)
    probe = _Probe()
    probe._resolved_command = ("/tools/probe", "wrap")
    return probe, seen


def test_version_probe_passes_the_flag_after_the_full_command(monkeypatch):
    probe, seen = _with_version_output(monkeypatch, stdout="1.2.3\n")
    probe.version_flag = "-V"

    assert probe.binary_version() == "1.2.3"
    assert seen[0][0] == ["/tools/probe", "wrap", "-V"]
    assert seen[0][1]["timeout"] == 10


def test_unavailable_scanner_is_not_probed(monkeypatch):
    """No command means no subprocess at all, and no version."""
    probe, seen = _with_version_output(monkeypatch, stdout="1.0")
    probe._resolved_command = ()

    assert probe.binary_version() is None
    assert seen == []


def test_failed_version_probe_is_not_a_version(monkeypatch):
    """A nonzero exit's stderr must not land in the version column."""
    probe, _ = _with_version_output(
        monkeypatch, stdout="", stderr="Error: unknown flag: --version", returncode=2
    )

    assert probe.binary_version() is None


def test_ansi_only_first_line_is_skipped(monkeypatch):
    """njsscan-style output: a bare colour line, then the version.

    Prevents the scanner version being recorded as '[34m'.
    """
    probe, _ = _with_version_output(monkeypatch, stdout="\x1b[34m\n\x1b[0mnjsscan 0.4.3\x1b[0m\n")

    assert probe.binary_version() == "njsscan 0.4.3"


def test_version_falls_back_to_stderr_when_stdout_is_empty(monkeypatch):
    probe, _ = _with_version_output(monkeypatch, stdout="", stderr="tool 9.9\n")

    assert probe.binary_version() == "tool 9.9"


def test_version_prefers_stdout_over_stderr(monkeypatch):
    probe, _ = _with_version_output(monkeypatch, stdout="out 1\n", stderr="err 2\n")

    assert probe.binary_version() == "out 1"


def test_blank_output_yields_no_version(monkeypatch):
    probe, _ = _with_version_output(monkeypatch, stdout="\n  \n\x1b[0m\n")

    assert probe.binary_version() is None


def test_missing_executable_during_probe_is_contained(monkeypatch):
    def boom(*a, **k):
        raise FileNotFoundError("gone")

    monkeypatch.setattr(_resolution.subprocess, "run", boom)
    probe = _Probe()
    probe._resolved_command = ("/tools/probe",)

    assert probe.binary_version() is None
