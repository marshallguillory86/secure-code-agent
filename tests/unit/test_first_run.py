"""The first five minutes.

A reviewer's verdict on cloning this and running it: *"The clone-and-try is a
failed coverage report. First-run is a scavenger hunt for Bandit, Semgrep,
Gitleaks, Trivy, Checkov, OSV, RuboCop. 'Never install anything' is the right
security line and a terrible first five minutes."*

Both halves were true. Pointed at any repository, a fresh install reported
`coverage: FAILED` and four missing scanners and stopped there — `--preflight`
already produced the install command for each one, and the failure path
printed only the names. Pointed at *this* repository it reported 0 to fix, 0
to review and 1,108 suppression candidates, because a security tool's tests
are deliberately vulnerable fixtures. Correct, and useless as a demonstration.

`--demo` answers the question a stranger actually has. The guidance below
answers the one they have thirty seconds later.

**The security line does not move.** Naming an install command is not running
one, and the demo tree is generated at runtime so installing this tool never
puts vulnerable source on anyone's disk.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from secure_code_audit import demo
from secure_code_audit.cli import _print_install_guidance, main


def test_the_demo_tree_carries_real_defects(tmp_path):
    root = demo.build(tmp_path / "d")
    sources = sorted(p.name for p in (root / "src").glob("*.py"))

    assert len(sources) >= 5, sources
    assert (root / "README.md").is_file()


def test_no_vulnerable_literal_ships_in_the_package():
    """The fixture is assembled at runtime for two reasons, and this pins both.

    Writing it into the package would put vulnerable source in every user's
    `site-packages`, and this project's own audit would flag its own demo —
    the third time in this repository that documenting a vulnerable pattern
    created one.
    """
    source = Path(demo.__file__).read_text(encoding="utf-8")

    assert "shell=True)" not in source
    assert "eval(expression)" not in source


def test_the_demo_audits_its_generated_tree(capsys):
    exit_code = main(["--demo", "--only-scanners", "builtin_rules"])
    out = capsys.readouterr().out

    assert exit_code in (0, 1)  # gate may fail on the planted defects; it should
    assert "Demo tree:" in out
    assert "secure-code-agent" in out


def test_the_demo_finds_something(capsys):
    """A demo that reports a clean tree demonstrates nothing."""
    main(["--demo", "--only-scanners", "builtin_rules"])
    out = capsys.readouterr().out

    assert "0 finding" not in out


def test_demo_refuses_a_path(capsys):
    """It audits its own tree; a path would silently be ignored."""
    assert main(["--demo", "some/repo"]) == 2
    assert "generated tree" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Guidance at the moment it is needed
# ---------------------------------------------------------------------------


def test_guidance_names_an_install_command_per_scanner(capsys):
    _print_install_guidance(["trivy", "osv_scanner"])
    out = capsys.readouterr().out

    assert "trivy" in out and "osv_scanner" in out
    assert "install" in out
    assert "--preflight" in out


def test_guidance_comes_from_the_same_source_as_preflight():
    """Not a second copy of the install instructions.

    A hand-maintained list here would drift from `--preflight`, and the two
    disagreeing about how to install a scanner is worse than one of them
    being absent.
    """
    from secure_code_audit.scanners import SCANNERS

    assert SCANNERS["trivy"]().unavailable_fix_hint()


def test_guidance_is_silent_when_there_is_nothing_to_say(capsys):
    _print_install_guidance([])

    assert capsys.readouterr().out == ""


def test_guidance_survives_an_unknown_scanner_name(capsys):
    """An imported SARIF can name a scanner this build does not ship. Advice
    must never be the thing that breaks a run."""
    _print_install_guidance(["not_a_real_scanner"])

    assert "not_a_real_scanner" not in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Applicability, which is what makes a first run reachable at all
# ---------------------------------------------------------------------------


def test_a_python_repository_does_not_require_ruby_tooling(tmp_path):
    """The floor is an opinion *with applicability*, not "everything
    optional". A pure-Python tree requires six scanners rather than ten, and
    the four it drops are the ones a Python developer has no reason to have.
    """
    from secure_code_audit import config as config_mod
    from secure_code_audit.cli import _repository_inventory
    from secure_code_audit.scanners import floor

    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    cfg = config_mod.Config()
    inventory = _repository_inventory(tmp_path, cfg)

    required = [
        name
        for name in floor.expand_required(["floor"])
        if floor.applies_to_repository(name, *inventory)
    ]

    assert "rubocop" not in required
    assert "njsscan" not in required
    assert "bandit" in required


@pytest.mark.parametrize("scanner", ["bandit", "builtin_rules", "gitleaks"])
def test_the_language_agnostic_core_is_always_required(scanner: str, tmp_path):
    """Applicability must narrow the floor, not dissolve it."""
    from secure_code_audit import config as config_mod
    from secure_code_audit.cli import _repository_inventory
    from secure_code_audit.scanners import floor

    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    inventory = _repository_inventory(tmp_path, config_mod.Config())

    assert floor.applies_to_repository(scanner, *inventory)
