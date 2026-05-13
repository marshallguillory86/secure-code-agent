# secure-code-agent

> **Deterministic security gate + bounded AI remediation prompts for repos with AI coding agents in the loop.**
> Anchored to NIST SSDF · OWASP ASVS · OWASP Top 10 · MITRE CWE Top 25 · OpenSSF Scorecard · SARIF 2.1.0.

```bash
pip install secure-code-agent

secure-code-agent --fail-on-gate \
    --output secure-code-report.md \
    --prompt-output secure-code-remediation-prompt.md \
    --sarif-output secure-code.sarif
```

The sibling of [`maintainability-agent`](https://github.com/marshallguillory86/maintainability-agent). Same shape: deterministic CI gate · plain-file outputs · per-host skill bundle. Different concern: security, not maintainability.

---

## Why this exists

AI coding agents ship code at human-review-saturating speed. Point them at a security finding and the documented anti-patterns are:

| Anti-pattern                                       | What the agent actually does                                                                       |
|----------------------------------------------------|----------------------------------------------------------------------------------------------------|
| **Crypto roulette**                                | "Replace MD5 with SHA-256" → rewrites the hashing module to use a library it saw in training data.|
| **Auth-flow rewrite**                              | "Fix the IDOR" → refactors the session model. Now you have an unaudited new auth path.            |
| **Validation softening**                           | "Make the tests pass after the fix" → weakens the regex / removes the bounds check.               |
| **Test deletion**                                  | "The security test is failing" → deletes the test.                                                 |
| **Lint disable**                                   | "This rule fires repeatedly" → `# nosec`, `# noqa`, `eslint-disable` everywhere.                  |
| **Scope creep**                                    | "I fixed the SQLi" → followed by 600 lines of unrelated refactoring.                              |
| **Dependency thrash**                              | "Bumping the vulnerable package" → introduces 12 unrelated new dependencies.                       |
| **Silent behavior change**                         | "It works now" → same input, different output. Downstream callers break.                          |

Existing scanners (Semgrep, Bandit, CodeQL, Snyk, Trivy) emit findings. None of them ship a **bounded prompt back to the agent** that says *"fix only these specific findings, do not touch crypto/auth/validation/logging, preserve behavior."*

That gap is what this tool fills.

## The output that matters

Every other security scanner stops at "here's a list of findings." `secure-code-agent` generates a remediation prompt:

```markdown
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
   already-vendored libraries.
8. Preserve behavior. Same inputs must produce the same outputs
   unless a finding explicitly proves the current behavior is unsafe.
9. Add a focused test that exercises the specific security boundary
   you fixed. The test must FAIL on the pre-fix code and PASS on
   the post-fix code. No "TODO: add test later".
10. Keep the patch small. If you find yourself rewriting a function
    rather than patching it, stop and report the structural issue.

## §FINDINGS
...
```

Hand the prompt to Claude Code, Codex, Cursor, Copilot, or any agent. The agent now has explicit boundaries. The full template + rationale lives in [`docs/remediation.md`](docs/remediation.md).

## Standards anchored, not invented

Every finding maps to five public standards. Operators see *which standard is failing*, not just *which scanner shouted*.

| Source                                       | What we use it for                                       |
|----------------------------------------------|----------------------------------------------------------|
| [NIST SSDF SP 800-218](https://csrc.nist.gov/pubs/sp/800/218/final) | Process practice id (e.g. `PW.5.1`) |
| [OWASP Top 10 (2021)](https://owasp.org/Top10/2021/) | Risk bucket (e.g. `A03:2021-Injection`) |
| [OWASP ASVS 5.0](https://github.com/OWASP/ASVS) | Verification requirement (e.g. `V5.3`) |
| [MITRE CWE Top 25 (2025)](https://cwe.mitre.org/top25/) | Canonical weakness id — the dedupe key |
| [OpenSSF Scorecard](https://openssf.org/projects/scorecard/) | Repo + supply-chain hygiene |
| [SARIF 2.1.0](https://www.oasis-open.org/standard/sarif-v2-1-0/) | Output format (and external scanner ingest) |

When Semgrep, CodeQL, and Bandit fire on the same SQL-injection sink with three different rule ids, they all map to `CWE-89` and the scorer counts **one** underlying weakness. Not three.

## Architecture (orchestrator, not engine)

```text
┌────────────────────────────────────────────────────────────────────┐
│  secure-code-agent CLI                                              │
│                                                                     │
│  Config → Scanners (subprocess) → Findings → Scoring → Renderers   │
│                                                                     │
│                                            ┌──────────────────┐    │
│                                            │ Markdown report  │    │
│                                            │ JSON             │    │
│                                            │ SARIF 2.1.0      │    │
│                                            │ PR comment       │    │
│                                            │ Remediation 🪄    │    │
│                                            │ Agent standards  │    │
│                                            └──────────────────┘    │
└────────────────────────────────────────────────────────────────────┘
        │
        │   Scanners (subprocess, version-isolated):
        │
        ├── Bandit            (Python SAST)
        ├── Semgrep           (multi-language SAST + SARIF ingest)
        ├── pip-audit         (Python SCA)
        ├── npm audit         (Node SCA)
        ├── Gitleaks          (secret scanning, history-aware)
        ├── TruffleHog        (verified secret scanning)
        ├── Trivy             (containers / IaC / k8s / vuln / secret)
        ├── Checkov           (Terraform / CloudFormation / Helm / k8s)
        ├── Hadolint          (Dockerfile lint)
        ├── OSV-Scanner       (multi-ecosystem SCA via osv.dev)
        ├── OpenSSF Scorecard (repo hygiene + supply chain)
        ├── eslint-plugin-security  (JS/TS SAST)                     [v0.3]
        ├── CodeQL SARIF      (ingest GitHub-hosted analysis)
        └── Built-in regex rules (high-confidence, low-FP)
```

We don't reimplement SAST. We invoke best-in-class scanners as subprocesses, parse their canonical output, normalize across CWE/OWASP/ASVS/SSDF, and produce one ranked view.

Full architecture in [`docs/design.md`](docs/design.md).

## Audit categories (9 buckets, 1 grade)

Findings roll up to nine canonical categories. The grade is driven by the **worst category** — one CRITICAL secret in git history shouldn't be offset by a clean dependency tree.

| Category                | Examples                                                                        |
|-------------------------|---------------------------------------------------------------------------------|
| `secrets`               | Hardcoded API keys, tokens in history, `.env` committed                         |
| `dependencies`          | CVE in pinned dep, yanked package, abandoned upstream                           |
| `code_vulnerabilities`  | SQLi, XSS, command-injection, path-traversal, SSRF, XXE, deserialization        |
| `auth_authz`            | Missing auth gate, IDOR, broken access control, JWT misuse                      |
| `crypto`                | Weak alg, hardcoded IV, ECB, MD5/SHA-1 for security, missing constant-time      |
| `supply_chain`          | Unpinned action, missing SBOM, no signed releases, low Scorecard                |
| `config_iac`            | World-readable S3, public security group, Dockerfile `USER root`, k8s privileged|
| `logging_observability` | Secrets in logs, PII in URLs, missing audit trail on auth events                |
| `policy_docs`           | Missing SECURITY.md, no responsible-disclosure path, no threat model            |

Scoring math + worked examples in [`docs/scoring.md`](docs/scoring.md).

## Hard gates

```json
{
  "gates": {
    "fail_on_severity":    ["critical", "high"],
    "fail_on_category":    ["secrets", "auth_authz"],
    "fail_on_new":         true,
    "min_score":           4.0,
    "require_scanners":    ["bandit", "gitleaks"],
    "max_unsuppressed":    { "critical": 0, "high": 0, "medium": 10 }
  }
}
```

Any tripped gate is a nonzero exit. Compose freely.

## Suppressions you can't game

`.scignore.yaml` — every suppression requires a `reason` AND an `expires` date (max 365 days). Past-expiry suppressions become CRITICAL findings on their own. You can't ship `reason: "we'll fix it later"` forever.

```yaml
- file: services/legacy_billing.py
  rule_id: "*"
  reason:  "Slated for rewrite Q3 2026 — gated by initiative INV-44."
  expires: "2026-09-30"

- rule_id: "B101"
  paths:   ["tests/"]
  reason:  "assert statements are legitimate in test code."
  expires: "2027-05-13"
```

Wildcard rule (`rule_id: "*"`) requires a `file` or `paths` scope — you cannot disable a rule globally.

## Baseline + incremental adoption

`secure-code-baseline.json` fingerprints every current finding. On the next run:

- Findings present in baseline → **acknowledged**; don't trip `fail_on_new`.
- Findings missing from baseline → **new**; trip the gate.

Bumping a CRITICAL or HIGH finding into the baseline requires `--bump-baseline --i-acknowledge-risk`. The bump records the operator's git `user.email` per fingerprint so PR review can see who acknowledged what.

This lets legacy repos adopt the gate without a 200-finding day-one cleanup.

## Quickstart

```bash
# Install
pip install secure-code-agent

# Initialize agent standards files for your AI coding tools
secure-code-agent --init-agent-standards \
    --target codex --target claude-code --target cursor --target copilot

# Run an audit with hard-gate exit
secure-code-agent --config secure-code-agent.json \
    --fail-on-gate \
    --output secure-code-report.md \
    --json-output secure-code-report.json \
    --sarif-output secure-code.sarif \
    --comment-output secure-code-pr-comment.md \
    --prompt-output secure-code-remediation-prompt.md

# Audit only changed files since main
secure-code-agent --changed-only main...HEAD --fail-on-new

# Ingest external scanner SARIF (CodeQL, Snyk, Trivy, etc.)
secure-code-agent --sarif-import codeql-results.sarif \
                   --sarif-import snyk-results.sarif
```

## Invokable skill / slash command

For agents that support invokable skills, this repo ships a portable skill under [`skills/secure-code-agent/`](skills/secure-code-agent/). The `SKILL.md` body is the source of truth; per-host adapters live under `agents/` and `copilot/`.

| Host                      | Install destination                                                                 | Invocation                          |
|---------------------------|-------------------------------------------------------------------------------------|-------------------------------------|
| Codex / OpenAI            | wired via `skills/secure-code-agent/agents/openai.yaml`                             | per Codex's skills convention       |
| Claude Code               | `cp -r skills/secure-code-agent ~/.claude/skills/`                                  | `/secure-code-agent`                |
| GitHub Copilot (VS Code)  | `cp skills/secure-code-agent/copilot/secure-code-agent.prompt.md .github/prompts/`  | `/secure-code-agent` in Copilot Chat |

## GitHub Action

```yaml
- uses: marshallguillory86/secure-code-agent@v0.1.0
  with:
    config: secure-code-agent.json
    changed-only: main...HEAD
    fail-on-gate: true
```

The action uploads SARIF to GitHub Code Scanning by default. See [`action.yml`](action.yml) and [`examples/github-actions/`](examples/github-actions/) for full workflows.

## What this is NOT

- ❌ **Not a SAST engine.** We delegate to Semgrep / Bandit / CodeQL / etc. — we don't write yet another AST analyzer.
- ❌ **Not a runtime defense.** No WAF, no IDS, no agent in the request path. Static + supply-chain + config only.
- ❌ **Not a SaaS.** Findings live as files in your repo. No telemetry. No version-check ping.
- ❌ **Not a license scanner.** Pair with `pip-licenses` / `license-checker` separately.
- ❌ **Not an exploit generator.** No DAST, no fuzzing.

## Design principles

1. **Deterministic first, AI optional.** The audit never calls an LLM by default. The remediation prompt is a generated artifact you choose to hand to an agent.
2. **Bounded scope.** The remediation prompt explicitly forbids touching crypto, auth, validation, logging, and tests.
3. **Standards-anchored.** Five public standards (NIST / OWASP-x3 / CWE) — no invented taxonomy.
4. **CWE-deduped scoring.** One underlying weakness = one finding, regardless of how many scanners found it.
5. **No vendor lock-in.** Markdown, JSON, SARIF, plain files. Pipe anywhere.
6. **CI-first, local-first.** Same binary in pre-commit, local CI, GitHub Actions, GitLab, Buildkite.

Full design philosophy in [`docs/design.md`](docs/design.md).

## Documentation

- [`docs/design.md`](docs/design.md)              — Architecture + non-goals + scanner protocol
- [`docs/standards.md`](docs/standards.md)        — NIST SSDF / OWASP / CWE / Scorecard / SARIF citations
- [`docs/scoring.md`](docs/scoring.md)            — Weighting model + worked examples
- [`docs/scanners.md`](docs/scanners.md)          — Per-scanner integrations + caveats
- [`docs/remediation.md`](docs/remediation.md)    — The prompt template + failure-mode rationale
- [`docs/threat-model.md`](docs/threat-model.md)  — What we defend against (and what we don't)

## Versioning

- **Semver.** v0.x is pre-1.0 — the config schema may evolve. v1.0 locks it.
- **SARIF 2.1.0** output is pinned and validated against the OASIS schema in CI.

## Get in touch

- Bug reports / feature requests — [GitHub Issues](https://github.com/marshallguillory86/secure-code-agent/issues)
- Security vulnerabilities in this tool — see [`SECURITY.md`](SECURITY.md)

## License

MIT — see [`LICENSE`](LICENSE).

---

Built by [Marshall Guillory](https://github.com/marshallguillory86). The companion to [`maintainability-agent`](https://github.com/marshallguillory86/maintainability-agent) — both tools encode a single thesis: *AI agents need deterministic boundaries, not best-effort guardrails.*
