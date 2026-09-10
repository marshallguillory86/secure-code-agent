# secure-code-agent

> **Deterministic security gate + bounded AI remediation prompts for repos with AI coding agents in the loop.**
> Anchored to NIST SSDF · OWASP ASVS · OWASP Top 10 · MITRE CWE Top 25 · OpenSSF Scorecard · SARIF 2.1.0.

```bash
pip install 'secure-code-agent[required-scanners]'

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

Known rules map to fields from five public standards. Unmapped and scanner-control
findings retain null standards fields rather than receiving invented mappings.

A CWE comes from one of three places, in descending authority: an adapter's
explicit override, the curated map in `standards.py`, then whatever the
scanner itself declared. That last source was being discarded — Bandit
publishes a CWE for all ~70 of its plugins and gosec for every rule, and both
were dropped on the floor, leaving **14% of real findings with any CWE at
all** against a corpus measurement. Reading them takes it to 100%, and the
OWASP category is derived from the CWE using OWASP's own published
category-to-CWE lists where the curated map has none.

Derivation stops where the standard does. `CWE-703` — Bandit's classification
for a bare `assert` — belongs to no OWASP Top 10 category, so that field stays
null. 62% of findings carry an OWASP category and the rest say nothing, which
is the honest answer.

| Source                                       | What we use it for                                       |
|----------------------------------------------|----------------------------------------------------------|
| [NIST SSDF SP 800-218](https://csrc.nist.gov/pubs/sp/800/218/final) | Process practice id (e.g. `PW.5.1`) |
| [OWASP Top 10 (2021)](https://owasp.org/Top10/2021/) | Risk bucket (e.g. `A03:2021-Injection`) |
| [OWASP ASVS 5.0](https://github.com/OWASP/ASVS) | Verification requirement (e.g. `V5.3`) |
| [MITRE CWE Top 25 (2025)](https://cwe.mitre.org/top25/) | Canonical weakness id used in stable fingerprints |
| [OpenSSF Scorecard](https://openssf.org/projects/scorecard/) | Repo + supply-chain hygiene |
| [SARIF 2.1.0](https://www.oasis-open.org/standard/sarif-v2-1-0/) | Output format (and external scanner ingest) |

When scanners map a finding to `CWE-89`, the canonical CWE participates in its
stable fingerprint and baseline identity. Cross-scanner findings are not yet
collapsed before scoring; reports preserve the original scanner evidence.

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
        ├── njsscan           (JS/TS SAST, offline, no Node needed)
        ├── RuboCop           (Ruby security cops, --only Security)
        ├── gosec             (Go SAST — opt-in; needs the Go toolchain)
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

`require_scanners` is a coverage gate, not a vulnerability gate. A required
scanner must resolve and complete successfully. Missing executables, timeouts,
invalid output, unsupported inputs, or excluding the scanner with CLI filters
fail coverage. Optional scanner failures produce `PARTIAL` coverage without
turning a clean finding set into a false comprehensive result. Markdown and
JSON reports record each scanner's outcome, resolved command, and version.
When `require_scanners` is present it must name at least one scanner; an empty
list is rejected instead of silently removing the structural coverage gate.

External scanners are not bundled, and the agent never installs one for you —
a gate that fetches and runs binaries to satisfy its own coverage requirement
is the supply-chain risk it is supposed to catch. Resolution order is an
explicit `scanners.<name>.command`, the active `PATH`, then `python -m <module>`
for supported Python scanners. Relative executable paths resolve from the scan
target and are executed with `shell=False`.

`secure-code-agent --preflight` reports which enabled scanners resolve on this
host, with versions and the install command for anything missing, and exits
nonzero when a required scanner is unavailable — so a missing toolchain costs a
second instead of a full audit. Bandit and pip-audit install as
`secure-code-agent[required-scanners]`; Semgrep and Checkov add
`[python-scanners]`. The remaining scanners are standalone binaries that cannot
come from PyPI: install them with your package manager, or run their pinned
upstream CI action and feed us the SARIF, which counts as coverage:

```bash
secure-code-agent --fail-on-gate --sarif-import trivy.sarif
```

An import satisfies `require_scanners` for the tool that produced it. An
unreadable, malformed, or run-less import fails the gate rather than ingesting
nothing quietly, an import reporting its own `executionSuccessful: false` is
recorded as failed, and when a scanner reports both locally and by import the
worse outcome wins. See [`docs/scanners.md`](docs/scanners.md) for the full
install matrix.

```json
{
  "scanners": {
    "bandit": {
      "enabled": true,
      "command": [".audit-tools/bin/python", "-m", "bandit"]
    },
    "pip_audit": {
      "enabled": true,
      "command": [".audit-tools/bin/python", "-m", "pip_audit"],
      "mode": "project",
      "inputs": ["engine/pyproject.toml"]
    }
  }
}
```

The tool never downloads a scanner during an audit. Install and pin scanner
versions in the audit environment or CI image.

This repository's own CI audits `requirements-audit.txt`, which pins the
minimum supported runtime dependency version. Project mode remains available
for repositories whose `pyproject.toml` is their authoritative audit input.

## Time-bounded suppressions

`.scignore.yaml` — every suppression requires a `reason` AND an `expires` date (max 365 days). Past-expiry suppressions become CRITICAL findings on their own. You can't ship `reason: "we'll fix it later"` forever.

```yaml
- file: services/legacy_billing.py
  rule_id: "*"
  reason:  "Slated for rewrite Q3 2026 — gated by initiative INV-44."
  expires: "2026-09-30"

  fingerprint: 0aaa689f8a967d8c   # optional: pin to ONE finding (16 hex, from the report)

  line: 18                          # optional: with fingerprint, pins the exact location

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

`--bump-baseline` rewrites the baseline from the current findings. The file is
plain JSON and must be reviewed like any other security-policy change. This
release does not implement an interactive acknowledgment. Baseline entries
record the best-effort local Git email, while repository review policy remains
the approval boundary.

This lets legacy repos adopt the gate without a 200-finding day-one cleanup.

## Quickstart

```bash
# Install the orchestrator with its pinned default Bandit + pip-audit toolchain
pip install 'secure-code-agent[required-scanners]'

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

# Ingest external scanner SARIF (CodeQL, Snyk, Trivy, etc.)
secure-code-agent --sarif-import codeql-results.sarif \
                   --sarif-import snyk-results.sarif
```

`--changed-only` is reserved but not yet safely implemented. Passing it fails
with exit code 2 so a caller cannot accidentally treat an unscoped audit as a
changed-file audit.

The current orchestrator accepts one repository root per invocation. Multiple
positional roots fail with exit code 2 instead of silently ignoring coverage.

## Invokable skill / slash command

For agents that support invokable skills, this repo ships a portable skill under [`skills/secure-code-agent/`](skills/secure-code-agent/). The `SKILL.md` body is the source of truth; per-host adapters live under `agents/` and `copilot/`.

| Host                      | Install destination                                                                 | Invocation                          |
|---------------------------|-------------------------------------------------------------------------------------|-------------------------------------|
| Codex / OpenAI            | wired via `skills/secure-code-agent/agents/openai.yaml`                             | per Codex's skills convention       |
| Claude Code               | `cp -r skills/secure-code-agent ~/.claude/skills/`                                  | `/secure-code-agent`                |
| GitHub Copilot (VS Code)  | `cp skills/secure-code-agent/copilot/secure-code-agent.prompt.md .github/prompts/`  | `/secure-code-agent` in Copilot Chat |

## GitHub Action

```yaml
- uses: marshallguillory86/secure-code-agent@v0.3.0
  with:
    config: secure-code-agent.json
    fail-on-gate: true
```

The action installs the exact source bundled with the referenced action plus
the pinned `required-scanners` extra (Bandit and pip-audit),
emits Markdown, JSON, SARIF, PR-comment, and remediation artifacts, and uploads
SARIF by default. The calling workflow must grant `security-events: write` for
SARIF upload. Pin production usage to a full commit SHA; the version tag above
is shown for readability. See [`action.yml`](action.yml) and
[`examples/github-actions/`](examples/github-actions/) for full workflows.

## maintainability-agent integration

`maintainability-agent` declares Security a **delegated** pillar naming this
tool, and reports it as `NotApplicable` so silence is never read as safety.
This tool emits the artifact that completes the picture:

```bash
secure-code-agent . --security-pillar security-pillar.json
maintainability-agent . --security-pillar security-pillar.json
```

Standalone use is unaffected — without the flag nothing is written and every
other output is identical. MA never executes this tool, and this tool never
imports MA; two independently releasable packages exchanging one document.

The artifact carries **two values that are never averaged**: a practice level
read from configuration and CI (*is anything preventing the next
vulnerability?*) and a code condition read from the scanners (*what did they
find?*). `condition` is `null` whenever scanner coverage is incomplete — this
tool's score is a rate over findings, so removing scanners makes the raw number
go **up**, and an unscanned repository must not arrive at MA looking measured.

Full contract, invariants and the practice rubric:
[`docs/ma-integration.md`](docs/ma-integration.md).

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
4. **Stable finding identity.** CWE, normalized path, and normalized evidence form the baseline fingerprint. Cross-scanner score deduplication remains future work.
5. **No vendor lock-in.** Markdown, JSON, SARIF, plain files. Pipe anywhere.
6. **CI-first, local-first.** Same binary in pre-commit, local CI, GitHub Actions, GitLab, Buildkite.

Full design philosophy in [`docs/design.md`](docs/design.md).

## Documentation

- [`docs/product-intent.md`](docs/product-intent.md) — Why this exists, who it serves, what it refuses to become
- [`docs/decisions.md`](docs/decisions.md)        — Decision register: rulings the code alone cannot answer
- [`docs/ma-integration.md`](docs/ma-integration.md) — The `security-pillar.json` contract maintainability-agent reads
- [`docs/calibration.md`](docs/calibration.md)   — The calibration study, its corpus, and what it found
- [`docs/design.md`](docs/design.md)              — Architecture + non-goals + scanner protocol
- [`docs/architecture.md`](docs/architecture.md)  — Audit of the system as built + remediation sequence
- [`docs/release-blockers.md`](docs/release-blockers.md) — Open v0.3.0 release blockers (do not tag until closed)
- [`docs/standards.md`](docs/standards.md)        — NIST SSDF / OWASP / CWE / Scorecard / SARIF citations
- [`docs/scoring.md`](docs/scoring.md)            — Weighting model + worked examples
- [`docs/scanners.md`](docs/scanners.md)          — Per-scanner integrations + caveats
- [`docs/remediation.md`](docs/remediation.md)    — The prompt template + failure-mode rationale
- [`docs/threat-model.md`](docs/threat-model.md)  — What we defend against (and what we don't)

## Versioning

- **Semver.** v0.x is pre-1.0 — the config schema may evolve. v1.0 locks it.
- **SARIF 2.1.0-shaped** output is structurally unit-tested and round-tripped;
  full OASIS schema validation is not yet part of CI.

## Get in touch

- Bug reports / feature requests — [GitHub Issues](https://github.com/marshallguillory86/secure-code-agent/issues)
- Security vulnerabilities in this tool — see [`SECURITY.md`](SECURITY.md)

## License

MIT — see [`LICENSE`](LICENSE).

---

Built by [Marshall Guillory](https://github.com/marshallguillory86). The companion to [`maintainability-agent`](https://github.com/marshallguillory86/maintainability-agent) — both tools encode a single thesis: *AI agents need deterministic boundaries, not best-effort guardrails.*
