"""secure-code-agent — deterministic security gate + bounded AI remediation prompts."""

#: The only place the version is written. `pyproject.toml` derives it via
#: `[tool.setuptools.dynamic]`, so the two cannot drift.
#:
#: They did drift once, and it shipped: pyproject said 0.4.0 while this said
#: 0.3.0, so the released v0.4.0 wheel stamped 0.3.0 into every SARIF document,
#: every JSON report, the Markdown header, `--version`, and the
#: `security-pillar.json` handed to maintainability-agent. The release workflow
#: compared the tag against pyproject's line and never looked here — it
#: verified the half that was right and shipped the half that was wrong.
#:
#: PyPI is immutable, so 0.4.0 stays wrong. 0.5.0 is the first build whose
#: artifacts name their own producer correctly.
__version__ = "0.10.0"
