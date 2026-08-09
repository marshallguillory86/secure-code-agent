# secure-code-agent — Design Spec

> Status: **v0.1 — design locked, MVP in flight.**
> Companion docs: [`standards.md`](standards.md), [`scoring.md`](scoring.md), [`scanners.md`](scanners.md), [`remediation.md`](remediation.md), [`threat-model.md`](threat-model.md).

## 1. Problem

LLM coding agents (Claude Code, Codex, Copilot, Cursor, Windsurf, custom SDK agents) ship code at human-review-saturating speed. When you point them at a security finding, they routinely overcorrect: swap crypto libraries, rewrite authentication flows, weaken validation to make tests green, disable a "noisy" rule, or stage a 600-line refactor for a one-line CWE-89. Existing scanners (Semgrep, Bandit, CodeQL, Snyk, Trivy) emit findings — none of them ship a **bounded prompt back to the agent** that says *"fix only these specific findings, do not touch crypto/auth/validation/logging, preserve behavior."*

That gap is what this tool fills. It is the security sibling of [`maintainability-agent`](https://github.com/marshallguillory86/maintainability-agent): a deterministic CI gate that orchestrates best-in-class scanners, normalizes their output across CWE / OWASP / NIST taxonomies, scores the repo, and — most importantly — generates a remediation prompt scoped to the actual findings with explicit guardrails against the failure modes above.

## 2. Goals

1. **Deterministic first, AI optional.** The audit never calls an LLM by default. The remediation prompt is a generated artifact you choose to hand to an agent.
2. **Bounded scope.** The remediation prompt explicitly forbids touching crypto, auth, validation, logging, and tests unless a finding names them as the defect.
3. **Standards-anchored.** Findings map to a canonical taxonomy: CWE id, OWASP Top 10 category, OWASP ASVS section, NIST SSDF practice. Operators see *which standard is failing*, not just *which scanner shouted*.
4. **Scanner-agnostic orchestration.** SARIF 2.1.0 in, SARIF 2.1.0 out. The tool is a scoring + remediation layer; we don't write yet another SAST engine.
5. **Stable finding identity.** Canonical CWE, normalized path, and normalized evidence form the baseline fingerprint. Cross-scanner findings remain separate in scoring in the current release.
6. **No vendor lock-in.** Markdown, JSON, SARIF, PR-comment, baseline — all plain files. Pair with mature scanners; don't replace them.
7. **CI-first, local-first.** Same binary in local pre-commit, local CI, GitHub Actions, GitLab, Buildkite. No SaaS round-trip required.

## 3. Non-goals

- **Not a SAST engine.** No custom AST analysis. We delegate to Semgrep / Bandit / CodeQL / etc.
- **Not a runtime defense.** No WAF, no IDS, no agent in the request path. Static + supply-chain + config posture only.
- **Not a SaaS dashboard.** Findings live as files in your repo. Pipe them anywhere; we don't host.
- **Not a license scanner.** License compliance is a separate concern (see `pip-licenses`, `license-checker`). This tool focuses on *security* hygiene.
- **Not an exploit generator.** No DAST, no fuzzing, no PoC generation.

## 4. Architecture

```text
┌────────────────────────────────────────────────────────────────────────────┐
│  secure-code-agent CLI                                                     │
│                                                                            │
│  ┌──────────┐    ┌───────────┐    ┌────────────┐    ┌──────────────────┐ │
│  │  Config  │───▶│  Scanner  │───▶│  Findings  │───▶│  Scoring +       │ │
│  │  loader  │    │  runner   │    │  normalizer│    │  category map    │ │
│  └──────────┘    └───────────┘    └────────────┘    └──────────────────┘ │
│        │              │                  │                    │           │
│        │              │                  │                    ▼           │
│        │              │                  │           ┌──────────────────┐ │
│        │              │                  │           │  Baseline diff   │ │
│        │              │                  │           └──────────────────┘ │
│        │              │                  │                    │           │
│        │              │                  ▼                    ▼           │
│        │              │           ┌──────────────────────────────────┐   │
│        │              │           │  Renderers                       │   │
│        │              │           │   · Markdown report              │   │
│        │              │           │   · JSON                          │   │
│        │              │           │   · SARIF 2.1.0                  │   │
│        │              │           │   · PR comment                   │   │
│        │              │           │   · Remediation prompt (bounded) │   │
│        │              │           │   · Agent standards files        │   │
│        │              │           └──────────────────────────────────┘   │
│        ▼              ▼                                                   │
│  ┌──────────────────────────────────────────────────────────────────────┐│
│  │  Hard gate (exit code) — configurable per category/severity         ││
│  └──────────────────────────────────────────────────────────────────────┘│
└────────────────────────────────────────────────────────────────────────────┘
        │
        │   Scanners (subprocess, never imported as libraries):
        │
        ├── Bandit            (Python SAST)
        ├── Semgrep           (multi-language SAST, also ingests Semgrep Cloud SARIF)
        ├── pip-audit         (Python SCA)
        ├── npm audit         (Node SCA)
        ├── OSV-Scanner       (multi-ecosystem SCA via osv.dev)
        ├── Gitleaks          (secret scanning, history-aware)
        ├── TruffleHog        (secret scanning, entropy + verifiers)
        ├── Trivy             (containers / IaC / filesystem / Kubernetes)
        ├── Checkov           (IaC: Terraform / CloudFormation / Helm / Dockerfile)
        ├── Hadolint          (Dockerfile lint)
        ├── eslint-plugin-security  (JS/TS SAST via ESLint)
        ├── CodeQL (SARIF ingest only — CodeQL runs separately in CI)
        ├── OpenSSF Scorecard (repo hygiene + supply-chain)
        └── Built-in regex rules (rules/*.py — see scanners.md)
```

### 4.1 Why subprocess, not library imports?

Three reasons:

1. **Version isolation.** Bandit's API moves between minor versions; importing it pins your environment to whatever it pins. Subprocess + JSON output → stable contract.
2. **License surface.** Subprocess gives us MIT/Apache-2.0 separation; importing GPL-adjacent tools would contaminate.
3. **Local + CI parity.** The same `bandit --format json` call works whether the user has bandit in their venv, on their PATH, or in a Docker image. We don't care which.

### 4.2 Scanner protocol

Every scanner implements:

```python
class Scanner(Protocol):
    name: str
    binary: str
    def configure(self, target: Path, config: Config) -> None: ...
    def run(self, target: Path, config: Config) -> list[Finding]: ...
```

Missing binaries don't crash the audit — they emit a single `informational` finding (`tool_unavailable`) and the scanner is skipped. Scanner execution is reported separately from security findings as `COMPLETE`, `PARTIAL`, or `FAILED` coverage. Hard gates can require specific scanners (`require_scanners: ["bandit", "gitleaks"]`); required scanners must complete successfully, so unavailable, timed-out, failed, invalid-output, and not-applicable outcomes fail the gate.

### 4.3 Finding normalization

Every scanner output is converted to a canonical `Finding`:

```python
@dataclass(frozen=True)
class Finding:
    rule_id:          str             # scanner-local id (B608, generic.python.sql.tainted-sql-string)
    canonical_cwe:    str | None      # e.g. "CWE-89" — a fingerprint input when mapped
    owasp_top10:      str | None      # e.g. "A03:2021-Injection"
    asvs_section:    str | None       # e.g. "V5.3"
    nist_ssdf:       str | None       # e.g. "PW.5.1"
    category:         Category        # 1-of-9 high-level bucket
    severity:         Severity        # CRITICAL/HIGH/MEDIUM/LOW/INFO
    confidence:       Confidence      # HIGH/MEDIUM/LOW (per-scanner)
    message:          str
    file_path:        Path
    line_start:       int
    line_end:         int | None
    code_snippet:     str | None
    scanner:          str             # which tool emitted it
    fingerprint:      str             # for baseline identity
    suppressed:       bool            # acknowledged via .scignore.yaml
    suppression_note: str | None
```

`fingerprint` is `sha256((canonical_cwe or rule_id) + file_path + normalized_code)[:16]` — stable across whitespace-only edits and distinct across files. It supports baseline identity; the current scorer does not deduplicate findings.

## 5. Standards taxonomy

We anchor to five public standards, all reproduced under [`standards.md`](standards.md):

| Source                          | What we use it for                                                     |
|---------------------------------|------------------------------------------------------------------------|
| **NIST SSDF SP 800-218**        | Process-level mapping (which SSDF practice does this finding violate?) |
| **OWASP Top 10 (2021)**         | Web-app risk bucket — operator-friendly                                |
| **OWASP ASVS 5.0**              | Verification requirement (L1/L2/L3) per finding                        |
| **MITRE CWE Top 25 (2025)**     | Canonical weakness id used in stable fingerprints                      |
| **OpenSSF Scorecard checks**    | Repo hygiene + supply-chain integrity score                            |

The reviewed mapping table in `src/secure_code_audit/standards.py` translates
known scanner rule ids into available CWE, OWASP Top 10, ASVS, and SSDF fields.
Unmapped findings remain valid with null standards fields; adding a mapping is
a code and test change.

## 6. Audit categories

Findings roll up to **nine canonical categories**:

| Category               | Examples                                                                        | Default weight |
|------------------------|---------------------------------------------------------------------------------|---------------:|
| `secrets`              | Hardcoded API keys, tokens in history, .env in git                              |          1.5×  |
| `dependencies`         | CVE in pinned dep, yanked package, abandoned upstream                           |          1.0×  |
| `code_vulnerabilities` | SQLi, XSS, command-injection, path-traversal, SSRF, XXE, insecure deserialization |        1.5×  |
| `auth_authz`           | Missing auth gate, IDOR, broken access control, JWT misuse                      |          1.5×  |
| `crypto`               | Weak alg, hardcoded IV, ECB, MD5/SHA-1 for security, missing constant-time      |          1.5×  |
| `supply_chain`         | Unpinned action, missing SBOM, no signed releases, low Scorecard                |          0.8×  |
| `config_iac`           | World-readable S3, public security group, Dockerfile `USER root`, k8s privileged|          1.0×  |
| `logging_observability`| Secrets in logs, PII in URLs, missing audit trail on auth events                |          0.8×  |
| `policy_docs`          | Missing SECURITY.md, no responsible-disclosure path, no threat model            |          0.5×  |

Category weight × severity weight × confidence weight = finding score. Sum → category score → overall score. Math is in [`scoring.md`](scoring.md).

## 7. Scoring model

Letter grade A+ → F, mapped from a 0.0 → 5.0 axis (mirrors maintainability-agent so operators have one mental model). The 5.0 baseline is "clean across every category"; deductions are weighted finding totals normalized by code volume so a 100k-LOC repo isn't penalized for having more findings than a 1k-LOC one. Full math in [`scoring.md`](scoring.md).

## 8. Hard gates

Configurable boolean gates that fail CI:

```json
"gates": {
  "fail_on_severity":    ["critical", "high"],
  "fail_on_category":    ["secrets", "auth_authz"],
  "fail_on_new":         true,
  "min_score":           4.0,
  "require_scanners":    ["bandit", "gitleaks"],
  "max_unsuppressed":    { "high": 0, "medium": 10 }
}
```

Gates compose with OR semantics — any tripped gate is a non-zero exit.

## 9. Baseline + incremental adoption

`secure-code-baseline.json` fingerprints every current finding. On next run:

- Findings present in baseline → counted as `acknowledged`, do not trip `fail_on_new`.
- Findings missing from baseline → `new`. Trip the gate.
- Use `--bump-baseline` after an intentional accept (with operator initials + reason).

This lets legacy repos adopt the gate without a 200-finding day-one cleanup. Same pattern as maintainability-agent.

## 10. Suppressions (`.scignore.yaml`)

Per-file or per-rule suppression with mandatory justification:

```yaml
- file: services/legacy_billing.py
  rule_id: "*"
  reason:  "Slated for rewrite Q3 2026 — gated by initiative INV-44."
  expires: "2026-09-30"
- rule_id: "B101"   # assert_used — used pervasively in test fixtures
  paths:   ["tests/"]
  reason:  "assert statements legitimate in test code."
```

`expires` is required. Past-expiry suppressions become CRITICAL findings on their own — you can't ship `reason: "we'll fix it later"` forever.

## 11. Remediation prompt (the differentiator)

Full template in [`remediation.md`](remediation.md). Key guardrails the prompt embeds:

> **Hard constraints (the agent MUST NOT violate):**
> 1. Fix only the findings listed below. Do not touch unrelated code.
> 2. Do not change cryptographic algorithms, key derivation, IV/nonce handling, or padding modes unless a finding explicitly names them as the defect.
> 3. Do not change authentication flows, session handling, or authorization gates unless a finding explicitly names them.
> 4. Do not weaken input validation, output encoding, or logging to make existing tests pass.
> 5. Do not disable security tests, security lint rules, or remove `@_limiter.limit` / similar decorators.
> 6. Do not introduce new dependencies; prefer stdlib or already-vendored libraries.
> 7. Preserve behavior unless a finding proves the current behavior is unsafe.
> 8. Add a focused test that exercises the specific security boundary you fixed.

The prompt also injects the standards mapping for each finding so the agent can read the CWE/OWASP/ASVS context without round-tripping to the operator.

## 12. Outputs (every run can emit any subset)

| File                                  | Purpose                                                          |
|---------------------------------------|------------------------------------------------------------------|
| `secure-code-report.md`               | Operator-readable findings with code snippets, sorted by severity|
| `secure-code-report.json`             | Machine-readable canonical findings                              |
| `secure-code.sarif`                   | SARIF 2.1.0 for GitHub Code Scanning / IDE ingestion             |
| `secure-code-pr-comment.md`           | Short body for `gh pr comment`                                   |
| `secure-code-remediation-prompt.md`   | Bounded prompt for the AI agent                                  |
| `secure-code-baseline.json`           | Fingerprint snapshot for incremental adoption                    |
| Agent standards files                 | `AGENTS.md`, `CLAUDE.md`, `.cursor/rules/security.mdc`, `.github/copilot-instructions.md` security sections via `--init-agent-standards` |

## 13. CLI surface (locked)

```text
secure-code-agent [path]
  --config FILE                  Config file (default: secure-code-agent.json)
  --output FILE                  Markdown report path
  --json-output FILE             Canonical JSON path
  --sarif-output FILE            SARIF 2.1.0 path
  --comment-output FILE          PR-comment markdown path
  --prompt-output FILE           Remediation prompt path
  --baseline FILE                Read existing baseline
  --bump-baseline                Rewrite baseline from current findings
  --fail-on-gate                 Exit nonzero if any gate trips
  --fail-on-new                  Exit nonzero on findings not in baseline
  --changed-only REF             Reserved; currently fails explicitly because safe scoped execution is not implemented
  --target codex|claude-code|cursor|copilot|windsurf|generic
                                 Init agent standards file for that host
  --instructions-output-dir DIR  Where to write the agent standards file
  --skip-scanners NAME[,NAME]    Skip specific scanners
  --only-scanners  NAME[,NAME]   Only run specific scanners
  --severity-threshold LEVEL     Filter findings below this severity
  --json                         Pure-JSON to stdout (for scripting)
  --version
  --help
```

## 14. Threat model

The agent runs on developer machines and in CI. Threats we consider:

- **Malicious repo content.** Scanners exec'd as subprocesses with `cwd=target, env={cleared}, shell=False`. We never `eval` or `exec` repo content.
- **Output injection.** Markdown report renders code snippets with fenced blocks; PR-comment escapes for GitHub flavor.
- **Suppression bypass.** Operators can't suppress an entire category; they suppress specific rule+file with mandatory `expires` and `reason`. Expired suppressions become CRITICAL.
- **Baseline tampering.** Baseline is a checked-in artifact with operator-attributable diffs; reviewers must approve baseline changes.

Full threat model in [`threat-model.md`](threat-model.md).

## 15. Versioning + compatibility

- **Semver.** v0.x is pre-1.0 — config schema may evolve. v1.0 locks the schema.
- **SARIF 2.1.0.** Output format pinned; we emit OASIS-compliant SARIF that GitHub's code-scanning ingests directly.
- **Scanner contract.** We support the JSON output format documented in each scanner's *latest stable* docs. Breaking format changes upstream → minor-version bump here with a compat note.

## 16. Open questions (track in GH issues, not in this doc)

- Should the remediation prompt include reproducer test code, or only the finding? (Likely yes for HIGH/CRITICAL; cost/benefit pending.)
- How to handle CodeQL findings that only exist in GitHub's hosted DB and never run locally? (Currently: import SARIF artifact via `--sarif-import path/to/codeql.sarif`.)
- Should the agent ship a default `.scignore.yaml` for common framework false positives (FastAPI test fixtures, Django settings.py SECRET_KEY references, etc.)? Probably yes; v0.2.

---

This spec is the contract. Anything that doesn't match this doc is either (a) a documented v0.2 item, or (b) a bug.
