"""The offline profile's own regression suite.

Two properties, and the second is the one that matters. Proving a rule fires
is easy — a pattern broad enough to match anything fires reliably. Proving it
stays quiet on the safe form of the same call is where precision lives, and it
is the half that catches a rule that matched the *shape* of a call rather than
the unsafe thing about it.

These run only where semgrep is installed. That is a real gap in a local `pytest`
run, so CI has a dedicated job that installs it — see `.github/workflows/ci.yml`.
A skip nobody notices is how a ruleset rots.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from secure_code_audit import ruleset
from secure_code_audit.scanners.semgrep_scanner import offline_ruleset_path

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "semgrep-offline"


def _semgrep() -> list[str] | None:
    found = shutil.which("semgrep")
    if found:
        return [found]
    try:
        import semgrep  # noqa: F401
    except ImportError:
        return None
    return [sys.executable, "-m", "semgrep"]


requires_semgrep = pytest.mark.skipif(_semgrep() is None, reason="semgrep is not installed")


def _scan(tmp_path: Path, fixture_dir: str) -> set[str]:
    """Rule ids that fired against a fixture directory.

    Fixtures are copied out of `tests/` first: semgrep's default ignore list
    excludes test directories, so scanning them in place silently reports zero
    findings — which looked exactly like every rule being broken.
    """
    target = tmp_path / "tree"
    target.mkdir()
    for path in (FIXTURES / fixture_dir).iterdir():
        shutil.copy(path, target / path.name)

    command = _semgrep()
    assert command is not None
    result = subprocess.run(
        [
            *command,
            "--config",
            str(offline_ruleset_path()),
            "--no-rewrite-rule-ids",
            "--metrics=off",
            "--json",
            "--quiet",
            str(target),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert result.stdout, f"semgrep produced no JSON: {result.stderr[:400]}"
    return {finding["check_id"] for finding in json.loads(result.stdout)["results"]}


def _declared_rules() -> list[dict]:
    return yaml.safe_load(offline_ruleset_path().read_text(encoding="utf-8"))["rules"]


@requires_semgrep
def test_every_rule_fires_on_the_vulnerable_fixture(tmp_path):
    declared = {rule["id"] for rule in _declared_rules()}

    fired = _scan(tmp_path, "positive")

    assert declared - fired == set(), "rules that never fire are worse than no rules"


@requires_semgrep
def test_no_rule_fires_on_the_safe_fixture(tmp_path):
    # Each safe function is deliberately close to its vulnerable twin, so a
    # rule matching the shape of a call rather than its danger fails here.
    assert _scan(tmp_path, "negative") == set()


@requires_semgrep
def test_the_ruleset_is_accepted_by_the_engine_that_will_run_it(tmp_path):
    command = _semgrep()
    assert command is not None
    result = subprocess.run(
        [*command, "--validate", "--config", str(offline_ruleset_path()), "--metrics=off"],
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr[:500]


def test_every_rule_carries_the_metadata_the_profile_promises():
    for rule in _declared_rules():
        rule_id = rule["id"]
        assert rule_id.startswith("sca.offline."), rule_id
        meta = rule.get("metadata") or {}
        # The mapping is the reason a small set is worth having: registry rules
        # deliver CWEs inconsistently, which is why every semgrep finding used
        # to arrive unmapped.
        assert str(meta.get("cwe", "")).startswith("CWE-"), f"{rule_id} has no CWE"
        assert meta.get("owasp"), f"{rule_id} has no OWASP bucket"
        assert meta.get("confidence") in {"HIGH", "MEDIUM", "LOW"}, rule_id
        assert meta.get("version"), f"{rule_id} carries no version"
        assert rule.get("severity") in {"ERROR", "WARNING", "INFO"}, rule_id
        assert rule.get("languages"), rule_id


def test_the_offline_profile_refuses_framework_rules():
    """D9: the offline floor takes language primitives, not framework APIs.

    Framework rules rot with every framework release, and framework breadth is
    what the online registry path is for. This is the enforceable half of that
    bound — a rule naming a framework fails the build rather than being caught
    in review, or not.
    """
    frameworks = (
        "django",
        "flask",
        "fastapi",
        "express",
        "spring",
        "rails",
        "laravel",
        "symfony",
    )
    body = offline_ruleset_path().read_text(encoding="utf-8").lower()
    for rule in _declared_rules():
        for name in frameworks:
            assert name not in rule["id"].lower(), f"{rule['id']} names a framework"
    # The patterns themselves, not just the ids.
    for name in frameworks:
        assert f"{name}." not in body, f"a rule pattern references {name}"


def test_the_profile_identifies_itself_by_version_and_digest():
    profile = ruleset.describe(offline_ruleset_path())

    assert profile is not None
    assert profile.id == ruleset.PROFILE_ID
    assert profile.version == ruleset.PROFILE_VERSION
    assert len(profile.digest) == 64
    assert profile.rule_count == len(_declared_rules())
    # An audit cites the profile the way a STIG result cites its benchmark.
    assert profile.cite().startswith(f"{ruleset.PROFILE_ID}@{ruleset.PROFILE_VERSION}")


def test_a_changed_ruleset_changes_the_digest(tmp_path):
    """The digest is evidence; the version is only an assertion.

    Someone editing a ruleset inside an installed wheel leaves the version
    saying 1.0.0. The digest is what notices.
    """
    original = offline_ruleset_path()
    edited = tmp_path / "edited.yaml"
    edited.write_text(original.read_text(encoding="utf-8") + "\n# an edit\n", encoding="utf-8")

    assert ruleset.describe(edited).digest != ruleset.describe(original).digest


def test_a_missing_ruleset_is_labelled_not_raised(tmp_path):
    assert ruleset.describe(tmp_path / "absent.yaml") is None
