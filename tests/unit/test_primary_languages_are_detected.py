"""Which languages the scored tree actually contains.

Coverage cannot say whether a tree was covered without knowing what is in
it. This is the input to that: the file extensions of the **primary** tree,
scoped exactly as the scoring denominator is.

Primary only, deliberately. A Go fixture under `tests/` does not mean a
Python project needs `gosec` — the test tree is reported and not scored, so
a language appearing only there cannot make the score unsupported. Same
reasoning as `loc_under`'s split: the numerator and the denominator have to
describe the same tree, and so does the coverage claim about them.
"""

from __future__ import annotations

from secure_code_audit.git_tools import extensions_under
from secure_code_audit.scanner_status import languages_for


def test_the_primary_tree_reports_its_own_extensions(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "b.go").write_text("package main\n", encoding="utf-8")

    found = extensions_under(tmp_path, (".py", ".go"), ())

    assert found == (".go", ".py"), found


def test_an_excluded_file_contributes_no_language(tmp_path):
    """`exclude_patterns` means not scanned, so not a coverage obligation."""
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    vendor = tmp_path / "vendor"
    vendor.mkdir()
    (vendor / "legacy.go").write_text("package main\n", encoding="utf-8")

    found = extensions_under(tmp_path, (".py", ".go"), ("vendor/",))

    assert found == (".py",), found


def test_the_test_tree_does_not_create_a_coverage_obligation(tmp_path):
    """A Go fixture under tests/ must not demand gosec of a Python project."""
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "fixture.go").write_text("package main\n", encoding="utf-8")

    found = extensions_under(tmp_path, (".py", ".go"), (), ("tests/",))

    assert found == (".py",), found


def test_an_extension_out_of_scope_is_ignored(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "notes.md").write_text("# hi\n", encoding="utf-8")

    assert extensions_under(tmp_path, (".py",), ()) == (".py",)


def test_a_single_file_target_reports_its_own_extension(tmp_path):
    """`rglob` on a file yields nothing — the bug `loc_under` documents."""
    one = tmp_path / "only.go"
    one.write_text("package main\n", encoding="utf-8")

    assert extensions_under(one, (".py", ".go"), ()) == (".go",)


# --- extension -> language -------------------------------------------------


def test_extensions_map_to_the_languages_the_floor_knows():
    got = languages_for((".py", ".go", ".rb", ".js", ".ts", ".java"))

    assert set(got) == {"python", "go", "ruby", "javascript", "typescript", "java"}


def test_an_extension_with_no_code_scanner_language_is_dropped():
    """YAML and Markdown are not code-vulnerability languages.

    They are covered on other axes by checkov and trivy. Mapping them to a
    language would make PARTIAL the permanent state of every repository.
    """
    assert languages_for((".yaml", ".json", ".md", ".txt")) == ()


def test_the_mapping_is_stable_and_deduplicated():
    """`.mjs` and `.js` are both JavaScript; the result names it once."""
    got = languages_for((".js", ".mjs", ".cjs", ".jsx"))

    assert got == ("javascript",), got
