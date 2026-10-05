"""Two finding shapes, each built in exactly one place.

MA found both as duplicate blocks, and both are the kind where the
duplication *is* the defect: fix a field in one copy, miss the other, and
two code paths disagree about what the same thing means.

**A dependency advisory** was built with the same seven fixed arguments at
four sites across `npm_audit`, `osv_scanner` and `pip_audit` — a 27-line
duplicate block. The dangerous field is `category=Category.DEPENDENCIES`:
that is what takes these off the code-condition score and onto their own
axis, because a CVE in a pinned dependency is fixed with a version bump and
an injection flaw is fixed with a rewrite. A site that drifted out of it
would be silently scored as shipped code.

**A synthetic suppression finding** was built twice in `suppressions.py`,
62 duplicated lines apart — and the second was written by copying the
first, which is how the pair came to exist at all.

Both now have one constructor. This is the lint that keeps it that way,
per the rule that an audit finding a bug class ships a check which blocks
the class rather than only fixing the instances.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SRC = REPO / "src" / "secure_code_audit"

#: The one function allowed to build a dependency advisory.
DEPENDENCY_CONSTRUCTOR = "_dependency_finding"
#: The one function allowed to build a synthetic suppression finding.
SUPPRESSION_CONSTRUCTOR = "_suppression_finding"


def _python_sources() -> list[Path]:
    return sorted(SRC.rglob("*.py"))


def _enclosing_function(tree: ast.Module, node: ast.AST) -> str | None:
    """The name of the function a node sits inside, or None at module level."""
    for candidate in ast.walk(tree):
        if isinstance(candidate, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for inner in ast.walk(candidate):
                if inner is node:
                    return candidate.name
    return None


def _calls_with_keywords(path: Path, required: dict[str, str]) -> list[tuple[str, int]]:
    """`(enclosing function, line)` for each call carrying all of `required`.

    Matched on the *keyword set* rather than on text, so reformatting or
    reordering the arguments cannot hide a hand-built copy.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    hits: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        supplied = {kw.arg: ast.unparse(kw.value) for kw in node.keywords if kw.arg is not None}
        if all(supplied.get(name) == value for name, value in required.items()):
            hits.append((_enclosing_function(tree, node) or "<module>", node.lineno))
    return hits


def test_the_source_tree_is_not_empty():
    """A glob that matched nothing would make both checks below vacuous."""
    assert len(_python_sources()) >= 20, len(_python_sources())


def test_only_one_function_builds_a_dependency_advisory():
    """Prevents a fourth hand-built copy, and the axis drift it would cause."""
    offenders: list[str] = []
    for path in _python_sources():
        for function, line in _calls_with_keywords(
            path,
            {
                "category": "Category.DEPENDENCIES",
                "line_start": "0",
                "confidence": "Confidence.HIGH",
            },
        ):
            if function != DEPENDENCY_CONSTRUCTOR:
                offenders.append(f"{path.relative_to(REPO)}:{line} in {function}()")

    assert offenders == [], (
        f"a dependency advisory is built outside {DEPENDENCY_CONSTRUCTOR}(): {offenders}. "
        "Call it instead — the DEPENDENCIES category is what keeps these off the "
        "code-condition score, and a drifted copy is scored as shipped code."
    )


def test_only_one_function_builds_a_synthetic_suppression_finding():
    """Prevents the copy-the-other-one path that created the first pair."""
    offenders: list[str] = []
    for path in _python_sources():
        for function, line in _calls_with_keywords(path, {"scanner": "'suppressions'"}):
            if function != SUPPRESSION_CONSTRUCTOR:
                offenders.append(f"{path.relative_to(REPO)}:{line} in {function}()")

    assert offenders == [], (
        f"a suppressions finding is built outside {SUPPRESSION_CONSTRUCTOR}(): "
        f"{offenders}. Both reporters share one constructor; pass what differs."
    )


@pytest.mark.parametrize(
    ("name", "module"),
    [
        (DEPENDENCY_CONSTRUCTOR, "scanners/_finding_builder.py"),
        (SUPPRESSION_CONSTRUCTOR, "suppressions.py"),
    ],
)
def test_each_constructor_exists_where_the_lint_expects_it(name: str, module: str):
    """The checks above pass trivially if the constructor was renamed away.

    Both assert "no call outside this function", which is satisfied by a
    function that no longer exists and a codebase with no calls at all.
    """
    tree = ast.parse((SRC / module).read_text(encoding="utf-8"))
    defined = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }

    assert name in defined, f"{name} is gone from {module}; the lint above now proves nothing"


def test_the_keyword_detector_actually_matches(tmp_path):
    """The falsifier.

    Both checks assert an empty list. A detector that matched nothing — a
    renamed keyword, a changed spelling of the enum — would pass for ever.
    This hands it a hand-built copy and requires a hit, then a near-miss and
    requires none.
    """
    offending = tmp_path / "offending.py"
    offending.write_text(
        "def scan(self):\n"
        "    return self._make_finding(\n"
        "        rule_id='x',\n"
        "        line_start=0,\n"
        "        confidence=Confidence.HIGH,\n"
        "        category=Category.DEPENDENCIES,\n"
        "    )\n",
        encoding="utf-8",
    )
    required = {
        "category": "Category.DEPENDENCIES",
        "line_start": "0",
        "confidence": "Confidence.HIGH",
    }

    assert _calls_with_keywords(offending, required) == [("scan", 2)]

    innocent = tmp_path / "innocent.py"
    innocent.write_text(
        "def scan(self):\n"
        "    return self._make_finding(\n"
        "        rule_id='x',\n"
        "        line_start=12,\n"
        "        confidence=Confidence.HIGH,\n"
        "        category=Category.CODE_VULNERABILITIES,\n"
        "    )\n",
        encoding="utf-8",
    )

    assert _calls_with_keywords(innocent, required) == []
