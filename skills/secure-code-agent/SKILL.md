---
name: secure-code-agent
description: Use when the agent needs to run or respond to secure-code-agent audits, generate bounded security remediation prompts, initialize per-agent security standards files, interpret findings against CWE/OWASP/ASVS/NIST-SSDF, or make small security fixes without crypto-roulette / auth rewrites / validation softening.
---

# Secure-Code Agent

## Purpose

Use the `secure-code-agent` CLI as the source of truth for deterministic
security audits and bounded remediation prompts. The tool wraps best-in-class
scanners (Bandit, Semgrep, pip-audit, npm audit, Gitleaks, built-in regex
rules, SARIF ingest from CodeQL/Snyk/Trivy) and normalizes their output across
CWE / OWASP Top 10 / OWASP ASVS / NIST SSDF.

**The remediation prompt is the differentiator.** It encodes hard constraints
against the documented anti-patterns for AI security fixes: crypto roulette,
auth-flow rewrites, validation softening, test deletion, lint disable, scope
creep, dependency thrash, silent behavior change.

## Core Workflow

1. Inspect the repo's existing instructions and config before running:
   - `AGENTS.md`, `CLAUDE.md`, `.github/copilot-instructions.md`, or other
     agent instruction files.
   - `secure-code-agent.json` when present.
   - `.scignore.yaml` (suppressions).
2. Prefer the repo's configured command when it exists. Otherwise:

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

3. For branch or PR work, pass `--changed-only REF` (e.g. `origin/main`). It
   scans the whole tree and scopes the *report* to what changed. It issues no
   grade, deliberately — a scoped run has no denominator it can defend. Pair
   it with `--fail-on-new` to gate on regressions.

4. If the audit emits `secure-code-remediation-prompt.md`, **read it before
   editing** and treat it as the bounded task.
5. Fix only the reported findings. Follow the hard constraints verbatim —
   they're not suggestions.
6. Re-run the audit and any native tests/lints required by the repo.
7. Report the commands run, whether the gate passed, and any remaining false
   positives or suppression candidates.

## Hard rules — non-negotiable

When fixing a security finding:

1. Fix only the findings listed. Do not touch unrelated code.
2. Do not change cryptographic algorithms, key derivation, IV/nonce handling,
   padding modes, or random sources unless a finding explicitly names them.
3. Do not change authentication flows, session handling, token lifetime,
   cookie attributes, or authorization gates unless a finding explicitly
   names them.
4. Do not weaken input validation, output encoding, sanitization, bounds
   checks, regex strictness, or rate limits to make existing tests pass.
5. Do not disable, delete, or skip security tests. Do not remove
   `@_limiter.limit`, `@require_auth`, `@require_csrf`, or similar decorators.
6. Do not silence linter warnings via `# nosec`, `# noqa`, `# type: ignore`,
   `eslint-disable`, `sonar-disable`.
7. Do not introduce new third-party dependencies. Prefer stdlib or
   already-vendored libraries.
8. Preserve behavior. Same inputs → same outputs unless a finding proves
   current behavior is unsafe.
9. Add a focused test that exercises the security boundary you fixed. The
   test must FAIL on pre-fix code and PASS on post-fix.
10. Keep the patch small. If you're rewriting a function rather than patching,
    stop and report.

## Installing or running

If `secure-code-agent` is missing from `PATH`, check the project docs first:

```bash
python3 -m pip install secure-code-agent
python3 -m pip install -e .
python3 -m secure_code_audit.cli --config secure-code-agent.json
```

## Generating per-agent standards

When asked to add AI-agent security standards, use the CLI rather than
hand-writing each file:

```bash
secure-code-agent --init-agent-standards \
  --target codex --target claude-code --target cursor \
  --target copilot --target windsurf
```

Generated standards are additive to repository-specific rules. Repo rules
win on conflict.

## Standards anchors

Every finding carries:
- **CWE id** — the dedupe key (https://cwe.mitre.org/)
- **OWASP Top 10** bucket (https://owasp.org/Top10/2021/)
- **OWASP ASVS section** (https://github.com/OWASP/ASVS)
- **NIST SSDF practice** (https://csrc.nist.gov/pubs/sp/800/218/final)

Read the linked standard before editing — it is the authoritative description
of the weakness, not the scanner's terse rule description.

## False positives

If a finding is a false positive, do NOT silently apply a fix. Add a
suppression entry to `.scignore.yaml` with:

- `rule_id` (or `*` scoped to `file`/`paths`)
- `reason` (required, non-empty, what's actually safe about this match)
- `expires` (required, ISO date, ≤ 365 days from today)

The operator will review the suppression in PR.

For interpretation guidance on categories + severity weighting, read
`references/finding-taxonomy.md`.
