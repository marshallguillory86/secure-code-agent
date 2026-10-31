## What this changes

<!-- The behaviour that moves, stated first, then why. Link the issue it closes: "Closes #123". -->

## How it is tested

<!-- The test that fails without this change and passes with it. A change with no behaviour to test says so and why. -->

## Checklist

- [ ] A failing test was written first and now passes; the full suite passes (`python -m pytest -q`).
- [ ] `python -m ruff check .` and `python -m ruff format --check .` are clean.
- [ ] The self-audit passes: `secure-code-agent --config secure-code-agent.json --fail-on-gate`.
- [ ] `CHANGELOG.md` has an entry under **Unreleased** for anything a user would notice.
- [ ] Documentation that describes the changed behaviour is updated, and `docs/html/` is re-rendered with `tools/render_docs.py`.
- [ ] No published number (score, grade, severity mapping) moves, or the PR says which one and why.
