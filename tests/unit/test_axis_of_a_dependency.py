"""A dependency advisory is not documentation.

`requirements.txt` matches the documentation pattern `**/*.txt`, and the axis
split read the path before the category — so every CVE in a pip manifest was
filed under **documentation**. Eighteen of them on a six-file demo tree, which
is how it was found: the demo shipped a pinned-vulnerable dependency and the
report said the vulnerabilities were docs.

It is a labelling defect rather than a scoring one — neither axis is scored —
but the label is the product here. A tool whose case is "we do not lie about
what we found" cannot file a vulnerable dependency under documentation.

The fix is ordering: classify by category first, and let the dependency axis
claim its own findings wherever the manifest lives.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from secure_code_audit.findings import Category, Confidence, Finding, Severity
from secure_code_audit.scoring import partition_by_path, split_side_axes


def _finding(path: str, category: Category) -> Finding:
    return Finding(
        rule_id="pip_audit.PYSEC-2018-28",
        scanner="pip_audit",
        fingerprint=f"fp:{path}",
        canonical_cwe="CWE-1104",
        owasp_top10="A06",
        asvs_section=None,
        nist_ssdf=None,
        category=category,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        file_path=Path(path),
        line_start=1,
        line_end=1,
        code_snippet=None,
        message="vulnerable dependency",
    )


def _classifier(docs_patterns=("**/*.txt", "**/*.md"), test_patterns=("tests/",)):
    """The production ordering, reduced: category first, then path."""
    from secure_code_audit.git_tools import is_test_path

    root = Path("/repo")

    def classify(finding: Finding) -> str:
        if finding.category is Category.DEPENDENCIES:
            return "primary"
        if is_test_path(finding.file_path, root, test_patterns):
            return "test tree"
        if is_test_path(finding.file_path, root, docs_patterns):
            return "documentation"
        return "primary"

    return classify


@pytest.mark.parametrize(
    "manifest",
    [
        "/repo/requirements.txt",
        "/repo/requirements-dev.txt",
        "/repo/docs/requirements.txt",
        "/repo/tests/requirements.txt",
    ],
)
def test_a_dependency_advisory_never_lands_on_a_path_axis(manifest: str):
    """Including under `docs/` and `tests/`, where the path rule is otherwise
    right. The dependency is vulnerable wherever it was declared."""
    findings = [_finding(manifest, Category.DEPENDENCIES)]

    primary, axes = partition_by_path(findings, _classifier())

    assert axes.get("documentation", []) == []
    assert axes.get("test tree", []) == []
    assert len(primary) == 1


def test_it_reaches_the_dependencies_axis():
    """Classifying as primary is only half: `split_side_axes` is what moves
    it onto its own axis, and it only ever saw the primary set."""
    findings = [_finding("/repo/requirements.txt", Category.DEPENDENCIES)]

    primary, _ = partition_by_path(findings, _classifier())
    scored, dependencies = split_side_axes(primary)

    assert len(dependencies) == 1
    assert scored == []


def test_a_real_documentation_finding_still_goes_to_documentation():
    """The fix must not empty the documentation axis. A secret in a tutorial
    is still a documentation finding."""
    findings = [_finding("/repo/docs/guide.md", Category.SECRETS)]

    _, axes = partition_by_path(findings, _classifier())

    assert len(axes.get("documentation", [])) == 1


def test_a_test_tree_finding_is_unaffected():
    findings = [_finding("/repo/tests/test_x.py", Category.CODE_VULNERABILITIES)]

    _, axes = partition_by_path(findings, _classifier())

    assert len(axes.get("test tree", [])) == 1


def test_the_ordering_is_what_matters():
    """Pins the cause, not just the symptom.

    Path-first classification sends the manifest to documentation; that is
    the version this replaces, and asserting it here means a revert fails
    with the reason attached rather than with a mystery count.
    """
    from secure_code_audit.git_tools import is_test_path

    root = Path("/repo")

    def path_first(finding: Finding) -> str:
        if is_test_path(finding.file_path, root, ("**/*.txt",)):
            return "documentation"
        return "primary"

    findings = [_finding("/repo/requirements.txt", Category.DEPENDENCIES)]
    _, axes = partition_by_path(findings, path_first)

    assert len(axes.get("documentation", [])) == 1, (
        "the old ordering no longer reproduces the defect; this test has stopped pinning anything"
    )
