"""This tool's own output is never its input, wherever it is stored.

`cli._own_artifacts` removes the paths the current run is about to write. That
stopped an audit scoring the report it had just produced — 446KB of quoted
findings, complete with the code snippets that produced them, in which
gitleaks duly found a "secret" at line 11,529.

It cannot see a **copy** kept somewhere else, and two independent reports of
that landed on the same day:

- this repository scanned `calibration/.corpus` — fourteen cloned third-party
  projects, 556,808 LOC and 550 findings, all about code that is not ours;
- `maintainability-agent` scanned `tools/validation/reports/` — 957,219 LOC of
  stored audit output *about other repositories*, 4,929 findings, which
  diluted five genuine criticals to an A-.

A stored report is the worst possible input: it quotes findings verbatim, so
it manufactures findings about findings, and it inflates the LOC denominator
that decides the grade at the same time.

The rule is structural rather than a list, because a list is what drifts:
every default output filename must be excluded by default, derived from
`DEFAULT_OUTPUTS`, so adding an output cannot leave a file this tool writes
readable by the next run.
"""

from __future__ import annotations

from pathlib import PurePosixPath

import pytest

from secure_code_audit.config import DEFAULT_EXCLUDES, DEFAULT_OUTPUTS, load
from secure_code_audit.git_tools import is_excluded

# ---------------------------------------------------------------------------
# The structural rule
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("key", sorted(DEFAULT_OUTPUTS))
def test_every_default_output_is_excluded_at_its_own_path(key: str, tmp_path):
    """Add an output, get an exclusion. This is the part that must not drift."""
    path = tmp_path / DEFAULT_OUTPUTS[key]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("x", encoding="utf-8")

    assert is_excluded(path, tmp_path, DEFAULT_EXCLUDES), (
        f"{DEFAULT_OUTPUTS[key]} would be scanned as source"
    )


#: Outputs whose *basename* this project owns, so a stored copy is ours
#: wherever it sits. `history_path` is excluded from this deliberately: it is
#: `.secure-code/history.jsonl`, and `history.jsonl` is not a name anybody
#: owns — matching it anywhere would exclude an unrelated file.
_OWNED_BASENAMES = sorted(k for k in DEFAULT_OUTPUTS if k != "history_path")


@pytest.mark.parametrize("key", _OWNED_BASENAMES)
def test_a_stored_copy_of_an_output_is_excluded_wherever_it_sits(key: str, tmp_path):
    """The case `_own_artifacts` cannot see.

    It removes the paths *this run* is about to write. An archived copy under
    some other directory is a different path, and it is the one that produced
    957,219 LOC of findings-about-findings on maintainability-agent.
    """
    name = PurePosixPath(DEFAULT_OUTPUTS[key]).name
    stored = tmp_path / "tools" / "validation" / "reports" / name
    stored.parent.mkdir(parents=True, exist_ok=True)
    stored.write_text("x", encoding="utf-8")

    assert is_excluded(stored, tmp_path, DEFAULT_EXCLUDES), (
        f"a stored copy of {name} would be scanned as source"
    )


def test_an_output_in_the_repository_root_is_excluded(tmp_path):
    """The ordinary case, which `_own_artifacts` also covers — belt and
    braces, because the two mechanisms have different lifetimes."""
    path = tmp_path / "secure-code-report.md"
    path.write_text("x", encoding="utf-8")

    assert is_excluded(path, tmp_path, DEFAULT_EXCLUDES)


@pytest.mark.parametrize("directory", [".secure-code", ".maintainability"])
def test_tool_state_directories_are_excluded(directory: str, tmp_path):
    """Both tools keep history, baselines and reports here, and all three
    quote finding text."""
    path = tmp_path / directory / "history.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("x", encoding="utf-8")

    assert is_excluded(path, tmp_path, DEFAULT_EXCLUDES)


def test_a_nested_tool_state_directory_is_excluded(tmp_path):
    """A monorepo puts these under each package, not only at the root."""
    path = tmp_path / "packages" / "api" / ".secure-code" / "history.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("x", encoding="utf-8")

    assert is_excluded(path, tmp_path, DEFAULT_EXCLUDES)


# ---------------------------------------------------------------------------
# The limit of the rule, stated so it is not mistaken for more
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("directory", ["vendor", "third_party", "libs/vendored"])
def test_vendored_code_is_not_excluded(directory: str, tmp_path):
    """Deliberately NOT excluded. Vendored code is deployed code, and hiding
    it by default would suppress real vulnerabilities in exactly the place
    nobody reads. Stored analysis output is not code at all; that is the
    whole distinction this module rests on."""
    path = tmp_path / directory / "app.py"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("x", encoding="utf-8")

    assert not is_excluded(path, tmp_path, DEFAULT_EXCLUDES)


def test_a_source_file_that_merely_mentions_a_report_is_not_excluded(tmp_path):
    """Matching is on the filename, not on content or on a prefix."""
    path = tmp_path / "src" / "secure_code_report_writer.py"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("x", encoding="utf-8")

    assert not is_excluded(path, tmp_path, DEFAULT_EXCLUDES)


# ---------------------------------------------------------------------------
# An operator can still say otherwise
# ---------------------------------------------------------------------------


def test_an_operator_exclude_list_replaces_the_defaults(tmp_path, monkeypatch):
    """Configuring `exclude_patterns` is choosing them. An operator who wants
    to audit stored reports — which is a legitimate thing to want once — can,
    and will not be silently given our list as well."""
    import json

    monkeypatch.chdir(tmp_path)
    (tmp_path / "secure-code-agent.json").write_text(
        json.dumps({"version": 1, "paths": {"exclude_patterns": ["node_modules/"]}}),
        encoding="utf-8",
    )

    assert load().exclude_patterns == ("node_modules/",)
