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


def _bandit() -> list[str] | None:
    found = shutil.which("bandit")
    if found:
        return [found]
    try:
        import bandit  # noqa: F401
    except ImportError:
        return None
    return [sys.executable, "-m", "bandit"]


@pytest.mark.skipif(_semgrep() is None or _bandit() is None, reason="needs both semgrep and bandit")
def test_no_python_rule_duplicates_bandit(tmp_path):
    """CONTRIBUTING has forbidden a parallel ruleset since the first commit.

    An earlier revision of this profile carried nineteen Python rules;
    seventeen duplicated Bandit, which is in the floor and is *already offline*
    — so the "offline coverage" argument that justified them was wrong. This
    test is that bound made enforceable: a Python rule flagging a line Bandit
    already flags is a rule we are maintaining for nothing.

    The gap this profile covers is the languages Bandit cannot read.
    """
    target = tmp_path / "tree"
    target.mkdir()
    for path in (FIXTURES / "positive").iterdir():
        shutil.copy(path, target / path.name)

    bandit_lines: set[int] = set()
    result = subprocess.run(
        [
            *_bandit(),
            "-r",
            str(target),
            "-f",
            "json",
            "-q",
            "--severity-level",
            "low",
            "--confidence-level",
            "low",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=300,
    )
    if result.stdout:
        bandit_lines = {r["line_number"] for r in json.loads(result.stdout)["results"]}

    ours = subprocess.run(
        [
            *_semgrep(),
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
    duplicated = {
        finding["check_id"]
        for finding in json.loads(ours.stdout)["results"]
        if ".python." in finding["check_id"] and finding["start"]["line"] in bandit_lines
    }

    assert duplicated == set(), (
        f"these Python rules duplicate Bandit, which is already in the floor "
        f"and already offline: {sorted(duplicated)}"
    )


def test_the_profile_covers_languages_the_floor_cannot_read_offline():
    """The justification for authoring rules at all, asserted.

    Three languages in the floor have an offline scanner of their own — Bandit
    for Python, njsscan for JavaScript, RuboCop's Security cops for Ruby — so a
    rule in one of those languages is only justified by a gap the tool leaves,
    and has to name it. Go and Java have no such tool: gosec needs the audited
    project's own toolchain and find-sec-bugs needs compiled bytecode, so rules
    there stand on their own (D12).
    """
    languages = {rule["id"].split(".")[2] for rule in _declared_rules()}

    assert {"javascript", "go", "ruby", "java"} <= languages
    for rule in _declared_rules():
        language = rule["id"].split(".")[2]
        if language not in _LANGUAGES_WITH_AN_OFFLINE_TOOL:
            continue
        assert (rule.get("metadata") or {}).get("covers-gap"), (
            f"{rule['id']} is a {language} rule, and "
            f"{_LANGUAGES_WITH_AN_OFFLINE_TOOL[language]} already scans "
            f"{language} offline. State the gap it leaves in a `covers-gap` "
            f"metadata field, or delete the rule."
        )


#: A language here has a floor tool that reads it offline, so a rule we write
#: for it must justify itself against that tool rather than against silence.
#: Measured in D12; JavaScript's entry is why four JS rules survived and three
#: did not.
_LANGUAGES_WITH_AN_OFFLINE_TOOL = {
    "python": "bandit",
    "javascript": "njsscan",
    "ruby": "rubocop",
}


def _njsscan() -> list[str] | None:
    found = shutil.which("njsscan")
    if found:
        return [found]
    try:
        import njsscan  # noqa: F401
    except ImportError:
        return None
    return [sys.executable, "-m", "njsscan"]


def _copied_fixtures(tmp_path: Path, which: str = "positive") -> Path:
    target = tmp_path / "tree"
    target.mkdir()
    for path in (FIXTURES / which).iterdir():
        shutil.copy(path, target / path.name)
    return target


def _our_findings(target: Path, language: str) -> dict[str, int]:
    """Our rule ids for one language, mapped to the line each fired on."""
    result = subprocess.run(
        [
            *_semgrep(),
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
    return {
        f["check_id"]: f["start"]["line"]
        for f in json.loads(result.stdout)["results"]
        if f".{language}." in f["check_id"]
    }


@pytest.mark.skipif(
    _semgrep() is None or _njsscan() is None, reason="needs both semgrep and njsscan"
)
def test_no_javascript_rule_duplicates_njsscan(tmp_path):
    """D12, made enforceable for JavaScript.

    njsscan is in the floor, installs as a Python package and needs no network
    and no Node runtime. Three of our JavaScript rules duplicated it and were
    deleted; this fails the build if another one is added.

    The four that remain survive because njsscan's exec / eval / DOM-XSS rules
    are taint rules gated on an Express `function ($REQ, $RES, ...)` shape, and
    its TLS rule matches only the `NODE_TLS_REJECT_UNAUTHORIZED` env form.
    """
    target = _copied_fixtures(tmp_path)

    result = subprocess.run(
        [*_njsscan(), "--json", str(target)],
        check=False,
        capture_output=True,
        text=True,
        timeout=300,
    )
    payload = json.loads(result.stdout)
    their_lines: set[int] = set()
    for bucket in ("nodejs", "templates"):
        for entry in (payload.get(bucket) or {}).values():
            for occurrence in entry.get("files") or []:
                their_lines.update(occurrence.get("match_lines") or [])

    duplicated = {
        rule_id
        for rule_id, line in _our_findings(target, "javascript").items()
        if line in their_lines
    }

    assert duplicated == set(), (
        f"these JavaScript rules duplicate njsscan, which is already in the "
        f"floor and already offline: {sorted(duplicated)}"
    )


@pytest.mark.skipif(
    _semgrep() is None or shutil.which("rubocop") is None, reason="needs both semgrep and rubocop"
)
def test_no_ruby_rule_duplicates_rubocop(tmp_path):
    """D12, made enforceable for Ruby.

    Run as `--only Security`, the same invocation the adapter uses. Two rules
    were deleted against this and one was narrowed: RuboCop's Security/Eval
    covers plain `eval` but reports nothing for `instance_eval` or
    `class_eval`, which is the ground our remaining rule stands on.
    """
    target = _copied_fixtures(tmp_path)

    result = subprocess.run(
        [
            "rubocop",
            "--only",
            "Security",
            "--format",
            "json",
            "--force-default-config",
            str(target),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=300,
    )
    their_lines = {
        offense["location"]["start_line"]
        for entry in json.loads(result.stdout).get("files", [])
        for offense in entry.get("offenses", [])
    }

    duplicated = {
        rule_id for rule_id, line in _our_findings(target, "ruby").items() if line in their_lines
    }

    assert duplicated == set(), (
        f"these Ruby rules duplicate RuboCop's Security cops, which are "
        f"already in the floor and already offline: {sorted(duplicated)}"
    )
