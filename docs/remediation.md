# Bounded remediation prompts

> Status: **v0.11.1 — 2026-09-11.** The bounded work order handed to an agent.

This is the differentiator. Every other scanner stops at "here's a list of findings." `secure-code-agent` generates an LLM-ready prompt scoped to the actual findings, with explicit guardrails against the failure modes that make AI security fixes worse than the bugs they patch.

## The failure modes we're constraining

When you point a generic LLM at a security finding, the documented anti-patterns are:

1. **Crypto roulette.** "Replace MD5 with SHA-256" turns into "rewrite the whole hashing module to use a library the agent has seen in training data." The new library may not be vendored, may have different padding semantics, and may not be FIPS-compliant.
2. **Auth-flow rewrites.** "Fix the IDOR" turns into "refactor the session model." Now you have an unaudited new auth path.
3. **Validation softening.** "Make these tests pass after your fix" — the agent weakens the regex / removes the bounds check / catches-and-ignores the exception until the test runs green.
4. **Test deletion.** "The security test is failing after my fix" — the agent deletes the test.
5. **Lint disable.** "This rule fires repeatedly" — the agent adds `# nosec`, `# noqa: B608`, `// eslint-disable-next-line` everywhere instead of fixing.
6. **Scope creep.** "I fixed the SQLi" — followed by 600 lines of "while I was in there" refactors.
7. **Dependency thrash.** "Bumping the vulnerable package" — agent introduces 12 unrelated new dependencies.
8. **Behavior change.** "It works now" — the function returns different output for the same input; downstream callers break silently.

The prompt template below is engineered specifically against each of these.

## Template

```
# Security remediation — bounded scope

You are fixing the security findings listed in §FINDINGS below.
This is a constrained task, not a refactor.

## Hard constraints (MUST NOT violate)

1. Fix only the findings listed in §FINDINGS. Do not touch unrelated
   code, files, or modules.
2. Do not change cryptographic algorithms, key derivation, IV/nonce
   handling, padding modes, or random sources unless a finding in
   §FINDINGS explicitly names them as the defect.
3. Do not change authentication flows, session handling, token
   lifetime, cookie attributes, or authorization gates unless a
   finding in §FINDINGS explicitly names them.
4. Do not weaken input validation, output encoding, sanitization,
   bounds checks, regex strictness, or rate limits to make existing
   tests pass.
5. Do not disable, delete, or skip security tests. Do not remove
   `@_limiter.limit`, `@require_auth`, `@require_csrf`, or similar
   decorators.
6. Do not silence linter warnings via `# nosec`, `# noqa`, `# type:
   ignore`, `eslint-disable`, `sonar-disable`, or equivalent.
7. Do not introduce new third-party dependencies. Prefer stdlib or
   already-vendored libraries. If a new dependency is necessary,
   stop and ask the operator first.
8. Preserve behavior. Same inputs must produce the same outputs
   unless a finding explicitly proves the current behavior is
   unsafe (in which case, name the input/output pair that changes
   in the patch description).
9. Add a focused test that exercises the specific security boundary
   you fixed. The test must FAIL on the pre-fix code and PASS on the
   post-fix code. No "TODO: add test later".
10. Keep the patch small. If you find yourself rewriting a function
    rather than patching it, stop and report the structural issue
    to the operator instead.

## Standards context

Each finding below carries its CWE id, OWASP Top 10 bucket, and
OWASP ASVS section. Read the standards entries (cited URLs) before
editing — they are the authoritative description of the weakness.

## Patch protocol

For each finding:

  1. Quote the specific lines you will change (file:line_start-line_end).
  2. State the minimum change that resolves the finding.
  3. State the test you will add.
  4. Apply the change.
  5. Run the test. Confirm it fails on the pre-fix code (via git stash
     or equivalent) and passes after.
  6. Re-run the audit (the operator's CI will do this — you don't need
     to invoke secure-code-agent yourself).

## Reporting

When done, emit a single summary block per finding:

  · Finding id:
  · Files changed (file:line ranges):
  · Test added (file:line range):
  · Behavior change (yes/no — if yes, name input → old output / new output):
  · Standards satisfied:

If you discover the finding is a false positive, do NOT apply a fix.
Instead, emit a suppression candidate for `.scignore.yaml` with the
justification and a proposed `expires` date (max 90 days). Operator
will review.

## §FINDINGS

{{For each finding, render:}}

### Finding {{n}}: {{rule_id}} — {{short_message}}

  **Severity:** {{severity}} ({{confidence}} confidence)
  **CWE:** [{{cwe}}](https://cwe.mitre.org/data/definitions/{{cwe_num}}.html)
  **OWASP Top 10:** [{{owasp_top10}}](https://owasp.org/Top10/{{owasp_year}}/)
  **OWASP ASVS:** [{{asvs_section}}](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x{{asvs_chapter}}.md#{{asvs_anchor}})
  **NIST SSDF:** [{{nist_ssdf}}](https://csrc.nist.gov/pubs/sp/800/218/final)
  **Scanner:** {{scanner}}
  **Category:** {{category}}

  **Location:** `{{file_path}}:{{line_start}}-{{line_end}}`

  ```{{language}}
  {{code_snippet}}
  ```

  **Why this matters:** {{standards.description}}

  **Suggested approach:** {{standards.fix_pattern}}
```

## What this prompt does NOT do

- It does not tell the agent *how* to fix each finding step-by-step. That would over-constrain — the agent often has better local context than the prompt author.
- It does not embed full file contents. The agent should `read` the cited file ranges.
- It does not include test code templates. The fix-and-test approach varies by finding type; templating it would produce brittle tests.
- It does not run the LLM for the operator. This is a generated artifact you choose to hand to your agent (Claude Code, Codex, Cursor, Copilot, custom SDK).

## Intended remediation boundaries

The template is designed around these representative cases:

1. **SQL injection** (CWE-89, HIGH) — agent must parameterize, not rewrite the query builder.
2. **Hardcoded API key** (CWE-798, CRITICAL) — agent must move to env var, not invent a "secrets manager" abstraction.
3. **`pickle.loads` on untrusted input** (CWE-502, HIGH) — agent must switch to JSON or signed payloads, NOT add a try/except around pickle.
4. **Missing CSRF on POST endpoint** (CWE-352, MEDIUM) — agent must add the existing middleware, NOT rewrite the routing.

Unit tests verify that the generated prompt retains its hard constraints and
finding evidence. The repository does not claim that these examples constitute
empirical LLM-behavior validation; agent outcomes still require human review.

## Per-agent skill bundles

The same prompt is packaged for direct invocation via host-specific skills:

| Agent           | Invocation                | Source                                                                              |
|-----------------|---------------------------|-------------------------------------------------------------------------------------|
| Codex / OpenAI  | `/secure-code-agent`      | `skills/secure-code-agent/` (Anthropic-format SKILL.md; works for Codex by convention)|
| Claude Code     | `/secure-code-agent`      | `~/.claude/skills/secure-code-agent/` (copy from `skills/secure-code-agent/`)        |
| Copilot Chat    | `/secure-code-agent`      | `.github/prompts/secure-code-agent.prompt.md` (from `skills/secure-code-agent/copilot/`) |
| Cursor          | follow agent instructions | `.cursor/rules/security.mdc` via `--init-agent-standards`                            |
| Windsurf        | follow agent instructions | `.windsurf/rules/security.md` via `--init-agent-standards`                           |

See [README.md](../README.md#invokable-skill--slash-command) for install destinations.
