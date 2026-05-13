# Contributing to secure-code-agent

Thanks for considering a contribution. Read this first.

## Scope

This project is an **orchestrator + scoring + remediation-prompt layer**.
It is NOT a SAST engine. PRs that propose:

- writing a new AST analyzer in Python
- shipping a parallel ruleset to Semgrep / Bandit / CodeQL
- adding a SaaS dashboard
- adding telemetry

…will be closed. See [`docs/design.md`](docs/design.md) for the non-goals.

## Adding a new scanner

The bar is high. Each new scanner must:

1. Have a documented JSON or SARIF output mode.
2. Be MIT/Apache-2.0/BSD licensed (no GPL — license-surface contamination).
3. Cover a category not already well-covered, OR materially raise precision
   in an existing category.

Steps:

1. Subclass `secure_code_audit.scanners.base.Scanner` in a new file under
   `src/secure_code_audit/scanners/`.
2. Add rule-id → standards mappings to `src/secure_code_audit/standards.py`.
3. Register in `src/secure_code_audit/scanners/__init__.py::SCANNERS`.
4. Add fixtures in `tests/fixtures/<scanner>/` with at least one HIGH true-
   positive, one false-positive that should be suppressible, and one parse-
   failure case.
5. Document the scanner in `docs/scanners.md`.

## Adding a built-in rule

Built-in rules are deliberately small + high-precision. Each new rule:

1. Targets a single CWE id.
2. Has ≥90% precision on a real codebase you can name.
3. Ships with a true-positive fixture and a false-positive fixture.
4. Has the CWE / OWASP / ASVS / SSDF mapping populated in `standards.py`.

## Code style

- Python 3.10+.
- `ruff` for lint + formatting (see `pyproject.toml`).
- Type hints required on public functions.
- Dataclasses for value objects; no plain dicts in the public API.

## Tests

- `pytest tests/ --cov=secure_code_audit --cov-fail-under=85`
- Unit tests for everything except subprocess-shelling-out (mock those).
- Integration tests for the SARIF emit/ingest roundtrip.
- Regression tests for scoring drift (`tests/integration/test_scoring_drift.py`).

## Commit messages

Conventional Commits:
- `feat(scanner): add trivy adapter`
- `fix(scoring): clamp normalized subtotal at 0`
- `docs(standards): refresh OWASP Top 10 anchor to 2024 cycle`

## Pull requests

- Keep PRs bounded — one concern per PR.
- Cite the standard / source for any new rule mapping.
- Update `CHANGELOG.md` under `## Unreleased`.

## Security disclosures

See [`SECURITY.md`](SECURITY.md). Do **not** open public issues for
vulnerabilities in this tool.

## License

Contributions are accepted under the MIT license. By submitting a PR you
agree your contribution may be distributed under MIT.
