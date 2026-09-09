# Contributing to secure-code-agent

Thanks for considering a contribution. Read this first.

## Scope

This project is an **orchestrator + scoring + remediation-prompt layer**.
It is NOT a SAST engine. PRs that propose:

- writing a new AST analyzer in Python
- shipping a parallel ruleset to Semgrep / Bandit / CodeQL — meaning **rules
  that duplicate detection a floor scanner already does**. Authoring rules for
  a gap no floor scanner covers is not this, and is how the offline profile
  exists at all; see [D11 and D12](docs/decisions.md). The test is measured,
  not argued: `test_no_python_rule_duplicates_bandit`,
  `test_no_javascript_rule_duplicates_njsscan` and
  `test_no_ruby_rule_duplicates_rubocop` each run the tool and fail the build
  on a rule flagging a line it already flags.

  **Before writing a rule, run the check.** Name the language, install the
  candidate FOSS tools, run them against the fixtures, and record the result.
  A gap has to be proven, not asserted — D11 was written after nineteen Python
  rules turned out to duplicate Bandit seventeen times, and D12 after the same
  mistake was repeated by *asserting* that four other languages had no offline
  tool. Two of them did.
- adding a SaaS dashboard
- adding telemetry

…will be closed. See [`docs/design.md`](docs/design.md) for the non-goals.

## Development setup

```bash
pip install -e ".[dev]"        # includes Bandit + pip-audit, so the repo can audit itself
secure-code-agent --preflight  # confirm the toolchain resolves before running an audit
pytest -q
ruff check . && ruff format --check .
```

`[dev]` pulls in `required-scanners` deliberately: a checkout that cannot run
its own gate is a checkout that will surprise you in CI. Optional Python
scanners come from `[python-scanners]`; standalone binaries are listed with
their install commands in [`docs/scanners.md`](docs/scanners.md).

## Adding a new scanner

The bar is high. Each new scanner must:

1. Have a documented JSON or SARIF output mode.
2. Satisfy the licence criteria below.
3. Cover a category not already well-covered, OR materially raise precision
   in an existing category. Where two tools answer the same question, the
   better one joins the floor and the other becomes opt-in with the reason it
   survived at all — see [`src/secure_code_audit/scanners/floor.py`](src/secure_code_audit/scanners/floor.py).

### Licence criteria

This rule used to read *"MIT/Apache-2.0/BSD licensed (no GPL — license-surface
contamination)"*. That was inherited from library-consuming projects and does
not describe this one, which links to no scanner, vendors no scanner source,
and distributes no scanner binary. Two shipped tools violated it while causing
no actual problem, which is how a rule teaches people to ignore rules. It is
replaced by three criteria keyed to **mechanism** rather than licence name.

1. **Any OSI-approved licence is acceptable for a tool we invoke as a
   subprocess and never distribute.** Copyleft reaches a combined work through
   linking, vendoring or bundling. Separate processes exchanging arguments and
   JSON are separate programs, and running `hadolint` no more makes this tool
   GPL than running `git` does. **Linking, vendoring or bundling still requires
   a permissive licence** — and if this project ever ships an image with
   scanners baked in, that image carries their obligations.
2. **AGPL tools are optional and off by default.** Not a legal judgement:
   AGPL §13 can create a source-offer obligation for anyone running this as a
   hosted service, and that is their decision to make rather than one we make
   silently on their behalf. Plenty of adopters also exclude AGPL by policy.
3. **Rule content and data are licensed separately from engines, and must be
   checked separately.** Semgrep is the live example — the engine is LGPL-2.1,
   but Semgrep-maintained registry rules have been under the Semgrep Rules
   Licence since December 2024, restricted to internal, non-competing,
   non-SaaS use. An engine's licence tells you nothing about the rules it
   fetches, and criterion 1 would have waved this through.

Record the licence of any new tool in `floor.py` alongside its rationale. See
[D6](docs/decisions.md).

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
