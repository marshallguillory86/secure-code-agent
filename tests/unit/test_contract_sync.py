"""Contracts written down twice, held in step by a test.

`docs/architecture.md` §3: "every contract has two or more sources of truth …
in each case the copies have already drifted."

Two of those rows are structural rather than fixable by deletion. The config
shape is declared by `config.py`'s dataclasses *and* by
`secure-code-agent.schema.json`, which editors read and the runtime does not.
The packaged data files are declared by `pyproject.toml`'s `package-data` and
by the directory actually existing.

**Generation was the doc's preferred fix and is not what this does.** The
schema is nested where `Config` is flat — `paths.include_extensions` and
`paths.exclude_patterns` are one JSON object and two dataclass fields, and
`gates`/`outputs` are free-form dicts with no dataclass at all. Generating one
from the other means writing a mapping layer that would itself be a third
source of truth. Asserting the agreement is smaller, catches the same drift
before it ships, and is honest about the shapes genuinely differing.
"""

from __future__ import annotations

import dataclasses
import json
from fnmatch import fnmatch
from pathlib import Path

import pytest

from secure_code_audit.config import _KNOWN_KEYS, Config, ScannerConfig
from secure_code_audit.scanners.semgrep_scanner import offline_ruleset_path

REPO = Path(__file__).resolve().parent.parent.parent
SCHEMA = json.loads((REPO / "secure-code-agent.schema.json").read_text(encoding="utf-8"))


def _pyproject() -> dict:
    """`tomllib` is 3.11+, and the support floor is 3.10.

    Skipping on the oldest interpreter only is deliberate: the check still runs
    on four of the five matrix versions, so it cannot rot unnoticed the way a
    blanket skip would.
    """
    tomllib = pytest.importorskip("tomllib", reason="tomllib is 3.11+")
    return tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))


def test_the_loader_and_the_schema_accept_the_same_top_level_keys():
    """A key one accepts and the other rejects is a bug either way round.

    Accepted by the loader but absent from the schema: the operator's editor
    marks valid config as invalid. Present in the schema but rejected by the
    loader: the editor blesses a key that makes the run exit 2. The schema
    already rejected its own `$schema` key once.
    """
    schema_keys = set(SCHEMA["properties"])

    assert schema_keys == set(_KNOWN_KEYS), {
        "only in schema": sorted(schema_keys - set(_KNOWN_KEYS)),
        "only in loader": sorted(set(_KNOWN_KEYS) - schema_keys),
    }
    # Both must be closed, or the agreement above proves nothing.
    assert SCHEMA.get("additionalProperties") is False


def _schema_scanner_properties() -> set[str]:
    node = SCHEMA["properties"]["scanners"]
    for key in ("additionalProperties", "patternProperties"):
        value = node.get(key)
        if isinstance(value, dict) and "properties" in value:
            return set(value["properties"])
        if isinstance(value, dict):
            found: set[str] = set()
            for sub in value.values():
                if isinstance(sub, dict) and "properties" in sub:
                    found |= set(sub["properties"])
            if found:
                return found
    raise AssertionError("could not locate per-scanner properties in the schema")


def test_the_paths_block_agrees_between_loader_and_schema():
    """`paths` is nested, so the top-level key check does not reach it.

    `test_patterns` was added to the dataclass, the loader and the schema in
    one change and this test still had to be told about it — which is the point:
    a `paths` sub-key that exists in only one of the three is exactly the drift
    §3 row 1 recorded, one level down where it is harder to see.
    """
    schema_paths = set(SCHEMA["properties"]["paths"]["properties"])
    loader_paths = {
        "include_extensions",
        "exclude_patterns",
        "test_patterns",
        "docs_patterns",
    }

    assert schema_paths == loader_paths, {
        "only in schema": sorted(schema_paths - loader_paths),
        "only in loader": sorted(loader_paths - schema_paths),
    }
    assert SCHEMA["properties"]["paths"].get("additionalProperties") is False


def test_the_scanner_config_dataclass_and_the_schema_agree():
    """The nested level drifts as easily as the top one, and less visibly."""
    code_fields = {field.name for field in dataclasses.fields(ScannerConfig)}
    schema_fields = _schema_scanner_properties()

    assert code_fields == schema_fields, {
        "only in schema": sorted(schema_fields - code_fields),
        "only in dataclass": sorted(code_fields - schema_fields),
    }


def test_every_config_dataclass_field_is_reachable_from_a_known_key():
    """No dataclass field is settable only by editing the source.

    `raw` and `source_path` are populated by the loader rather than by the
    operator, and `include_extensions`/`exclude_patterns` arrive nested under
    `paths` — everything else must correspond to a key an operator can write.
    """
    loader_populated = {"raw", "source_path", "trust_target_config"}
    nested_under_paths = {
        "include_extensions",
        "exclude_patterns",
        "test_patterns",
        "docs_patterns",
    }

    for field in dataclasses.fields(Config):
        if field.name in loader_populated or field.name in nested_under_paths:
            continue
        assert field.name in _KNOWN_KEYS, (
            f"Config.{field.name} has no configuration key; either add it to "
            f"_KNOWN_KEYS and the schema, or mark it loader-populated here"
        )


def test_the_offline_ruleset_is_declared_as_package_data():
    """A shipped wheel without the ruleset makes offline Semgrep fail closed.

    `offline_ruleset_path()` returns None when the file is missing and the
    adapter then refuses to run rather than reaching the network — correct, but
    it means dropping the `package-data` line breaks every installed user's
    offline mode while every test on a source checkout still passes, because a
    source checkout has the file either way.
    """
    globs = _pyproject()["tool"]["setuptools"]["package-data"]["secure_code_audit"]
    data_dir = REPO / "src" / "secure_code_audit" / "data"
    shipped = sorted(p for p in data_dir.iterdir() if p.is_file())

    assert shipped, "there is no data directory to ship"
    for path in shipped:
        relative = f"data/{path.name}"
        assert any(fnmatch(relative, glob) for glob in globs), (
            f"{relative} exists but no package-data glob matches it, so it "
            f"would be missing from a built wheel"
        )

    # And the loader can actually find it through the packaging machinery.
    assert offline_ruleset_path() is not None


def test_the_version_is_written_in_exactly_one_place():
    """Not "the two agree" — there is only one.

    The version was duplicated: `pyproject.toml` carried `version = "0.4.0"`
    while the package carried `0.3.0`. The released v0.4.0 wheel therefore
    stamped 0.3.0 into every SARIF document, every JSON report, the Markdown
    header, `--version` and the pillar artifact handed to
    maintainability-agent. The release workflow compared the tag against
    pyproject's line and never looked at the package, so it verified the half
    that was right and shipped the half that was wrong.

    An earlier fix asserted the two literals matched. That polices a
    duplication rather than removing it, and leaves the next person free to
    edit either one. pyproject now derives the version from the package via
    `[tool.setuptools.dynamic]`, so this asserts the duplication has not come
    back rather than that it is currently consistent.
    """
    project = _pyproject()["project"]

    assert "version" not in project, (
        "pyproject declares a literal version again; it must stay derived from "
        "secure_code_audit.__version__ via [tool.setuptools.dynamic]"
    )
    assert project.get("dynamic") == ["version"]
    assert (
        _pyproject()["tool"]["setuptools"]["dynamic"]["version"]["attr"]
        == "secure_code_audit.__version__"
    )


def test_the_build_stamps_the_package_version_into_its_metadata():
    """The property that actually failed, checked end to end.

    A single source of truth is only worth anything if the build honours it.
    This asserts the version setuptools would publish is the one the package
    reports — the exact comparison nobody was making when 0.4.0 shipped
    reporting 0.3.0.
    """
    from secure_code_audit import __version__

    attr = _pyproject()["tool"]["setuptools"]["dynamic"]["version"]["attr"]
    module_name, _, attribute = attr.rpartition(".")
    module = __import__(module_name, fromlist=[attribute])

    assert getattr(module, attribute) == __version__
    assert __version__.count(".") >= 2, f"{__version__!r} is not a release version"
