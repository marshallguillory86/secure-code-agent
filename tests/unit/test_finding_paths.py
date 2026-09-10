"""A finding's path must be anchored to the tree that was audited.

Adapters disagree about what to report and always will: Bandit, Semgrep,
RuboCop and the rest emit absolute paths, gitleaks emits paths relative to the
repository it scanned. Neither is wrong and neither is ours to change.

What *was* wrong is letting the difference through. Every consumer that asks
"where is this?" — `is_excluded`, `is_test_path`, the axis split — resolves a
relative path against the process working directory, so `relative_to(root)`
raised and the answer came back "no". Silently, and fail-open:

  * `exclude_patterns` did not apply to gitleaks findings at all. An operator
    excluding `vendor/` still had vendor secrets scored.
  * Across the calibration corpus, four `tests/certs/*.key` files in
    `requests` and six documentation examples in `flask` were scored as
    production secrets. Both repositories sat at F on that alone.

The audit that found this ships the lint, per the standing rule: fixing the
two adapters that happened to be wrong today would not stop the seventeenth
adapter from being wrong tomorrow. `Scanner._make_finding` is the one
constructor every adapter passes through, so the invariant is asserted there
and against the registry as a whole.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from secure_code_audit import scanners as registry
from secure_code_audit.config import Config
from secure_code_audit.git_tools import is_excluded, is_test_path
from secure_code_audit.scanners.base import Scanner


class _Probe(Scanner):
    """A minimal adapter, used only to reach the shared constructor."""

    name = "probe"
    binary = None

    def scan(self, target: Path, config: Config):  # pragma: no cover - unused
        raise NotImplementedError


def _probe(target: Path) -> _Probe:
    probe = _Probe()
    probe.configure(target, Config())
    return probe


def _finding(probe: _Probe, file_path: str):
    return probe._make_finding(
        rule_id="R1",
        message="m",
        file_path=Path(file_path),
        line_start=1,
        line_end=1,
        code_snippet=None,
    )


# ---------------------------------------------------------------------------
# The invariant
# ---------------------------------------------------------------------------


def test_a_relative_path_is_anchored_to_the_audited_tree(tmp_path):
    """gitleaks' shape. This is the case that was broken."""
    finding = _finding(_probe(tmp_path), "tests/certs/server.key")

    assert finding.file_path.is_absolute()
    assert finding.file_path == tmp_path / "tests" / "certs" / "server.key"


def test_an_absolute_path_inside_the_tree_is_left_alone(tmp_path):
    """Bandit's shape. Rooting an already-rooted path must be a no-op."""
    inside = tmp_path / "src" / "app.py"

    assert _finding(_probe(tmp_path), str(inside)).file_path == inside


def test_an_absolute_path_outside_the_tree_is_not_dragged_inside(tmp_path):
    """An imported SARIF may legitimately name another machine's checkout.

    Inventing a root for it would be worse than leaving it where it is: a
    finding relocated under our target would then be scored against a file
    that does not exist here.
    """
    elsewhere = Path("/somewhere/else/app.py")

    assert _finding(_probe(tmp_path), str(elsewhere)).file_path == elsewhere


def test_a_file_target_anchors_to_its_directory(tmp_path):
    """Auditing one file still gives paths a directory to be relative to."""
    single = tmp_path / "app.py"
    single.write_text("x = 1\n", encoding="utf-8")
    probe = _Probe()
    probe.configure(single, Config())

    assert _finding(probe, "helpers.py").file_path == tmp_path / "helpers.py"


def test_an_unconfigured_adapter_does_not_invent_a_root(tmp_path):
    """`configure()` is called by the CLI, not by the dataclass.

    A directly-constructed adapter has no target, and guessing one from the
    process working directory is the bug this module exists to prevent.
    """
    assert _finding(_Probe(), "a/b.py").file_path == Path("a/b.py")


# ---------------------------------------------------------------------------
# The consequence that made it matter
# ---------------------------------------------------------------------------


def test_an_unrooted_path_no_longer_escapes_the_exclude_rules(tmp_path):
    """The fail-open half, asserted directly on the path helpers.

    Both of these answered `False` for a relative path — not because the path
    was outside the tree, but because `Path.resolve()` had anchored it to
    whatever directory the operator ran the CLI from.
    """
    assert is_excluded(Path("vendor/thing.go"), tmp_path, ("vendor/",))
    assert is_test_path(Path("tests/certs/ca.key"), tmp_path, ("tests/",))


@pytest.mark.parametrize(
    ("relative", "pattern"),
    [
        ("context_test.go", "**/*_test.go"),
        ("conftest.py", "**/conftest.py"),
        ("app.test.ts", "**/*.test.ts"),
        ("router/context_test.go", "**/*_test.go"),
    ],
)
def test_double_star_includes_depth_zero(tmp_path, relative, pattern):
    """`**/` means "at any depth", and depth zero is a depth.

    `fnmatch` disagrees, because the pattern carries a literal `/`. Gin keeps
    its tests beside the code they test, so three of its four "production"
    secrets were root-level test fixtures — enough on its own to hold the
    repository at F.
    """
    assert is_excluded(tmp_path / relative, tmp_path, (pattern,))


# ---------------------------------------------------------------------------
# And for every adapter, not just the two that were wrong
# ---------------------------------------------------------------------------


def test_every_registered_adapter_builds_findings_through_the_rooting_constructor():
    """No adapter may construct a `Finding` directly.

    `_make_finding` is where the standards mapping, the fingerprint and now
    the path anchoring all happen. An adapter that bypasses it silently opts
    out of all three, which is how a `Finding(...)` call in one adapter could
    reintroduce this whole class of bug without failing a single test above.
    """
    import inspect

    offenders = []
    for name, cls in registry.SCANNERS.items():
        source = inspect.getsource(inspect.getmodule(cls))
        if "Finding(" in source.replace("_make_finding(", ""):
            offenders.append(name)

    assert offenders == [], (
        f"{offenders} construct Finding() directly instead of going through "
        f"Scanner._make_finding(), so their paths are never anchored to the "
        f"audited tree"
    )
