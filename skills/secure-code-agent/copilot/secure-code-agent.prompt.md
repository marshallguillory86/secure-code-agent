---
mode: agent
description: Run a secure-code-agent audit and apply only bounded remediation. Source of truth for security gates anchored to CWE / OWASP / NIST SSDF.
tools: ['workspace', 'terminal']
---

# Secure-Code Agent

Use the `secure-code-agent` CLI as the source of truth for deterministic
security audits + bounded remediation. Wraps Bandit, Semgrep, pip-audit,
npm audit, Gitleaks, built-in regex rules, and SARIF ingest from
CodeQL/Snyk/Trivy. Normalized output across CWE / OWASP Top 10 / OWASP
ASVS / NIST SSDF.

## Core Workflow

1. Inspect the repo's existing instructions and config before running:
   - `AGENTS.md`, `CLAUDE.md`, `.github/copilot-instructions.md`.
   - `secure-code-agent.json`.
   - `.scignore.yaml`.
2. Prefer the repo's configured command. Otherwise:

```bash
secure-code-agent \
  --config secure-code-agent.json \
  --fail-on-gate \
  --output secure-code-report.md \
  --json-output secure-code-report.json \
  --sarif-output secure-code.sarif \
  --prompt-output secure-code-remediation-prompt.md \
  --comment-output secure-code-pr-comment.md
```

3. `--changed-only` is reserved but not yet safely implemented and exits 2.
   Use a full audit with `--fail-on-new` for branch / PR work.
4. Read `secure-code-remediation-prompt.md` before editing — treat it
   as the bounded task brief.
5. Fix only the reported findings.
6. Re-run the audit and any native tests/lints.
7. Report commands run, gate pass/fail, residual false positives.

## Hard rules — non-negotiable when fixing security findings

1. Fix only the findings listed. Do not touch unrelated code.
2. Do not change cryptographic algorithms, KDF, IV/nonce handling,
   padding modes, or random sources unless a finding names them.
3. Do not change authentication flows, session handling, token lifetime,
   cookie attributes, or authorization gates unless a finding names them.
4. Do not weaken input validation, output encoding, sanitization, bounds
   checks, regex strictness, or rate limits to make existing tests pass.
5. Do not disable, delete, or skip security tests. Do not remove
   `@_limiter.limit`, `@require_auth`, `@require_csrf`, or similar.
6. Do not silence linter warnings via `# nosec`, `# noqa`, `# type: ignore`,
   `eslint-disable`, `sonar-disable`.
7. Do not introduce new third-party dependencies. Prefer stdlib or
   already-vendored libraries.
8. Preserve behavior. Same inputs → same outputs unless a finding proves
   current behavior is unsafe.
9. Add a focused test that exercises the security boundary you fixed.
   The test must FAIL pre-fix and PASS post-fix.
10. Keep the patch small.

## Installing or running

```bash
python3 -m pip install secure-code-agent
python3 -m pip install -e .
python3 -m secure_code_audit.cli --config secure-code-agent.json
```

## Generating per-agent standards

```bash
secure-code-agent --init-agent-standards \
  --target codex --target claude-code --target cursor \
  --target copilot --target windsurf
```

## False positives

Do NOT silently apply a fix. Add a `.scignore.yaml` entry with:
- `rule_id` (or `*` scoped to `file`/`paths`)
- `reason` (required, non-empty)
- `expires` (required, ISO date, ≤ 365 days)

Operator will review.
