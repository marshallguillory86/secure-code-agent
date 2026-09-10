"""secure-code-agent — deterministic security gate + bounded AI remediation prompts."""

#: Kept in step with `pyproject.toml` by `test_the_package_version_matches_pyproject`.
#:
#: This drifted once: pyproject moved to 0.4.0 and this string did not, so the
#: released v0.4.0 wheel reported itself as 0.3.0 in every SARIF document, every
#: JSON report, the Markdown header, `--version`, and the `security-pillar.json`
#: handed to maintainability-agent. The release workflow verifies the *tag*
#: against pyproject and never looked here, so nothing caught it.
#:
#: Reading it from `importlib.metadata` instead was tried and is worse: it
#: reports whatever distribution happens to be installed, which in a working
#: checkout was a stale 0.1.0. A version is provenance, and provenance that
#: depends on the reader's install state is not provenance. A literal plus a
#: test that fails on drift is both simpler and harder to get wrong.
__version__ = "0.4.0"
