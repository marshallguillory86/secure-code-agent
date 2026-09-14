"""A finding's path must be anchored to the repository that was audited.

Adapters disagree about what to report and always will: Bandit, Semgrep,
RuboCop and the rest emit absolute paths, gitleaks emits paths relative to the
repository it scanned. Neither is wrong and neither is ours to change.

What *was* wrong is letting the difference through. Every consumer that asks
"where is this?" — `is_excluded`, `is_test_path`, the axis split — resolved a
relative path against the process working directory, so `relative_to(root)`
raised and the answer came back "no". Silently, and fail-open:

  * `exclude_patterns` did not apply to gitleaks findings at all. An operator
    excluding `vendor/` still had vendor secrets scored.
  * Across the calibration corpus, four `tests/certs/*.key` files in
    `requests` and six documentation examples in `flask` were scored as
    production secrets. Both repositories sat at F on that alone.

The first fix (D5) made every path absolute inside `Scanner._make_finding`.
That anchored it, and chose the wrong convention: the adapters that build
through SARIF ingest never passed through it, and an absolute path is no
identity for anything compared across machines — a `paths:` suppression never
matched, and a fingerprint changed with the checkout directory. The invariant
is now repository-relative, set once by `findings.anchor` on everything the
CLI collects. The end-to-end half, over every registered scanner, is
`tests/integration/test_finding_paths_are_repository_relative.py`.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from secure_code_audit import scanners as registry
from secure_code_audit.config import Config
from secure_code_audit.findings import Finding, anchor, repository_path
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


def _located(reported: str | Path, root: Path, scanned: Path | None = None) -> Path:
    return repository_path(Path(reported), scanned=scanned or root, root=root)


def test_a_relative_path_is_taken_relative_to_the_scanned_tree(tmp_path):
    """gitleaks' `git` pass and SARIF ingest. The case D5 found broken."""
    assert _located("tests/certs/server.key", tmp_path) == Path("tests/certs/server.key")


def test_an_absolute_path_inside_the_tree_becomes_repository_relative(tmp_path):
    """Bandit's shape, and gitleaks' `dir` pass given an absolute root."""
    assert _located(tmp_path / "src" / "app.py", tmp_path) == Path("src/app.py")


def test_a_file_uri_is_a_path(tmp_path):
    """An imported SARIF may spell its location as a URI."""
    uri = (tmp_path / "src" / "my app.py").as_uri()

    assert _located(uri, tmp_path) == Path("src/my app.py")


def test_an_absolute_path_outside_the_tree_is_not_dragged_inside(tmp_path):
    """An imported SARIF may legitimately name another machine's checkout.

    Inventing a root for it would be worse than leaving it where it is: a
    finding relocated under our target would then be scored against a file
    that does not exist here.
    """
    elsewhere = Path("/somewhere/else/app.py")

    assert _located(elsewhere, tmp_path) == elsewhere


def test_a_subdirectory_audit_is_relative_to_the_repository_root(tmp_path):
    """`.scignore.yaml`, the baseline and `--changed-only` all live at the root."""
    scanned = tmp_path / "api"

    assert _located("handlers.py", tmp_path, scanned) == Path("api/handlers.py")
    assert _located(scanned / "handlers.py", tmp_path) == Path("api/handlers.py")


def test_a_file_target_anchors_to_its_directory(tmp_path):
    """Auditing one file still gives paths a directory to be relative to."""
    assert _located("helpers.py", tmp_path, scanned=tmp_path) == Path("helpers.py")


def test_an_adapter_keeps_the_path_it_was_given(tmp_path):
    """Anchoring is the CLI's job, once, not the constructor's.

    A directly-constructed adapter has no root, and guessing one from the
    process working directory is the bug this module exists to prevent.
    """
    assert _finding(_probe(tmp_path), "a/b.py").file_path == Path("a/b.py")
    assert _finding(_Probe(), "a/b.py").file_path == Path("a/b.py")


def test_anchoring_recomputes_a_path_derived_fingerprint(tmp_path):
    reported = _finding(_probe(tmp_path), str(tmp_path / "src" / "app.py"))

    (anchored,) = anchor([reported], scanned=tmp_path, root=tmp_path)

    assert anchored.file_path == Path("src/app.py")
    assert anchored.fingerprint == Finding.make_fingerprint(
        canonical_cwe=reported.canonical_cwe,
        rule_id=reported.rule_id,
        file_path=Path("src/app.py"),
        code_snippet=reported.code_snippet,
    )
    assert anchored.legacy_fingerprint(tmp_path) == reported.fingerprint


def test_anchoring_keeps_an_id_that_was_not_derived_from_the_path(tmp_path):
    """Control findings carry ids such as `unavailable.bandit`."""
    control = _Probe()._unavailable_finding(tmp_path)

    (anchored,) = anchor([control], scanned=tmp_path, root=tmp_path)

    assert anchored.file_path == Path(".")
    assert anchored.fingerprint == control.fingerprint


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


def test_every_registered_adapter_builds_findings_through_the_shared_constructor():
    """No adapter may construct a `Finding` directly.

    `_make_finding` is where the standards mapping and the fingerprint happen.
    An adapter that bypasses it silently opts out of both. Path anchoring is
    no longer here — `findings.anchor` covers adapters and SARIF imports alike
    — and the end-to-end test over the registry is what holds that.
    """
    import inspect

    offenders = []
    for name, cls in registry.SCANNERS.items():
        source = inspect.getsource(inspect.getmodule(cls))
        if "Finding(" in source.replace("_make_finding(", ""):
            offenders.append(name)

    assert offenders == [], (
        f"{offenders} construct Finding() directly instead of going through "
        f"Scanner._make_finding(), so they skip the standards mapping and the "
        f"shared fingerprint"
    )


# ---------------------------------------------------------------------------
# Version provenance
# ---------------------------------------------------------------------------


class _Versioned(_Probe):
    """An adapter whose --version output we control."""

    def __init__(self, stdout: str, returncode: int = 0):
        self._stdout = stdout
        self._returncode = returncode

    def is_available(self):
        return True

    def binary_version(self):
        import subprocess
        from unittest.mock import patch

        completed = subprocess.CompletedProcess(
            args=[], returncode=self._returncode, stdout=self._stdout, stderr=""
        )
        with patch("subprocess.run", return_value=completed):
            return Scanner.binary_version(self)


def test_a_colourised_version_is_recorded_as_a_version():
    """njsscan opens `--version` with a bare `\\x1b[34m` on its own line and
    puts the version on the next one, so taking line one recorded the
    scanner version as `[34m` — in the coverage block, in every report, and
    in a calibration study whose whole claim is that it re-derives from
    pinned inputs."""
    scanner = _Versioned("\x1b[34m\nnjsscan: v1.0.0 | Ajin Abraham\x1b[0m\n")

    assert scanner.binary_version() == "njsscan: v1.0.0 | Ajin Abraham"


def test_an_uncoloured_version_is_unchanged():
    assert _Versioned("gitleaks version 8.30.1\n").binary_version() == "gitleaks version 8.30.1"


def test_leading_blank_lines_are_skipped():
    assert _Versioned("\n\n  1.28.2  \n").binary_version() == "1.28.2"


def test_output_that_is_only_colour_is_not_a_version():
    """Better to say nothing than to record an escape sequence."""
    assert _Versioned("\x1b[34m\x1b[0m\n").binary_version() is None


def test_a_failed_probe_is_still_not_a_version():
    """Reporting stderr here once put "Error: unknown flag: --version" in the
    version column of a report claiming the scanner ran fine."""
    assert _Versioned("1.2.3", returncode=1).binary_version() is None


# ---------------------------------------------------------------------------
# The `python -m` fallback must actually run the tool
# ---------------------------------------------------------------------------


def test_semgrep_declares_no_python_module_fallback():
    """`python -m semgrep` was deprecated in 1.38.0 and now prints a notice,
    exits 0, and analyses nothing.

    The fallback fires whenever the module is importable but the binary is
    off PATH — the normal state after installing njsscan, which pulls
    semgrep in as a dependency. The outcome was FAILED rather than a silent
    COMPLETED, so coverage caught it and no grade was claimed on an unrun
    scanner; but it reported "semgrep failed" to an operator whose actual
    situation was "semgrep is not on PATH", and it turned five of this
    project's own tests from skipped into failing.
    """
    from secure_code_audit.scanners.semgrep_scanner import SemgrepScanner

    assert SemgrepScanner.python_module is None


def test_every_declared_python_module_fallback_can_actually_run():
    """A fallback that resolves but does nothing is worse than no fallback.

    Checks the module exposes a `__main__`, which is what `python -m`
    needs. It caught checkov, which ships none — `python -m checkov` fails
    with "No module named checkov.__main__" — and did so in CI, where the
    full floor is installed, after passing locally on a machine that did
    not have checkov.

    **This is necessary and not sufficient.** semgrep *has* a `__main__`;
    it simply prints a deprecation notice and analyses nothing, which no
    static check of this kind can see. That one was caught by running the
    thing. A declared fallback deserves both.
    """
    import importlib.util

    from secure_code_audit import scanners as registry

    for name, cls in registry.SCANNERS.items():
        module = getattr(cls, "python_module", None)
        if not module:
            continue
        if importlib.util.find_spec(module) is None:
            continue  # not installed here; nothing to check
        assert importlib.util.find_spec(f"{module}.__main__") is not None, (
            f"{name} declares python_module={module!r} but it has no __main__, "
            f"so `python -m {module}` cannot run it"
        )
