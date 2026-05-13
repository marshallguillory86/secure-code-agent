# Changelog

All notable changes to `secure-code-agent` are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/). Semver pre-1.0 — config
schema may evolve.

## 0.2.0 — 2026-05-13

The Tier-2 release. Six new scanners ship as full adapters with standards
mappings and mocked-subprocess test coverage.

### Added — Tier-2 scanners

- **Trivy** (`trivy`) — containers / filesystem / IaC scanning. SARIF-native;
  output is routed into `dependencies` / `config_iac` / `secrets` by rule-id
  prefix (CVE-/GHSA-/AVD-/secret).
- **Checkov** (`checkov`) — IaC misconfig scanning across Terraform /
  CloudFormation / Helm / k8s / Dockerfile. SARIF-native; all findings land
  in `config_iac`.
- **Hadolint** (`hadolint`) — Dockerfile linting. Twelve security-relevant
  rule ids (DL3002 `USER root` → HIGH, DL3025 shell-form CMD → MEDIUM, etc.)
  get specific severities; the remaining DL/SC rules fall through to LOW.
- **OSV-Scanner** (`osv_scanner`) — multi-ecosystem SCA via osv.dev. Overlaps
  pip-audit + npm-audit by design; the fingerprint dedupe across
  `(canonical_cwe, file_path, code_snippet)` prevents double-counting.
- **TruffleHog** (`trufflehog`) — verified secret scanning. Defaults to
  `--only-verified` so we ship live-confirmed matches at CRITICAL only;
  operators can opt into unverified via `extra_args: ["--no-only-verified"]`.
- **OpenSSF Scorecard** (`scorecard`) — repo + supply-chain hygiene. Special-
  cased to operate against a remote GitHub URL (auto-detected via
  `git remote get-url origin`). Score → severity: `<3 → HIGH`, `<7 → MEDIUM`,
  `<10 → LOW`, `10 → no finding`, `<0 → INFORMATIONAL` (inconclusive).

### Added — standards mappings

New (scanner, rule_id) → CWE/OWASP/ASVS/SSDF mappings for all six Tier-2
scanners. Scorecard checks get per-check mappings for `Branch-Protection`,
`Signed-Releases`, `Pinned-Dependencies`, `Token-Permissions`,
`Security-Policy`, `Dangerous-Workflow` plus a wildcard fallback.

### Fixed
- `owasp_url()` now generates a deep-link to the specific Top-10 bucket
  (`A03_2021-Injection`) instead of always returning the index URL.
- `fail_on_new` gate no longer trips on `INFORMATIONAL` findings (e.g.
  `tool_unavailable` notices). Those are awareness signals, not security
  defects.

### Refactored
- `scoring.evaluate_gates()` extracted into per-gate evaluators (cognitive
  complexity 17 → 8). Dogfooding the maintainability-agent standard.
- `sarif.ingest()` decomposed into `_finding_from_run`, `_finding_from_result`,
  `_severity_from_result`, `_cwe_from_rule`, `_location_from_result`
  (cognitive complexity 38 → 4 in the top-level function).

### Tests
- 15 new unit tests across the six Tier-2 scanners, covering: unavailable-
  binary path, SARIF/JSON output parsing, severity routing, category routing,
  empty-output handling.
- Total: 76 tests pass.

## 0.1.0 — 2026-05-13

Initial public release.

### Added
- Deterministic CLI gate over six Tier-1 scanners: Bandit, Semgrep, pip-audit,
  npm audit, Gitleaks, and a built-in regex rule pack.
- SARIF 2.1.0 emit + ingest. External SARIF (CodeQL, Snyk, Trivy, etc.) merges
  with locally-run findings via fingerprint dedupe.
- Standards taxonomy: every finding maps to a CWE id (dedupe key), OWASP Top
  10 bucket, OWASP ASVS section, and NIST SSDF practice. Top-25 CWEs get a
  1.25× scoring boost.
- Nine canonical audit categories: `secrets`, `dependencies`,
  `code_vulnerabilities`, `auth_authz`, `crypto`, `supply_chain`,
  `config_iac`, `logging_observability`, `policy_docs`.
- Scoring model with worst-category-drives-grade semantics (mirrors
  `maintainability-agent`'s pattern). Letter grade A+ → F.
- Hard gates: `fail_on_severity`, `fail_on_category`, `fail_on_new`,
  `min_score`, `max_unsuppressed`. Compose with OR semantics.
- Suppressions (`.scignore.yaml`) with mandatory `reason` + `expires`
  (max 365 days). Past-expiry suppressions become CRITICAL findings on
  their own.
- Baseline (`secure-code-baseline.json`) for incremental adoption.
  Per-fingerprint `bumped_by` records the operator's git `user.email`.
- Bounded remediation prompt generator (`secure-code-remediation-prompt.md`)
  — the differentiator. Hard constraints encoded against the documented
  AI-fix failure modes (crypto roulette, auth-flow rewrite, validation
  softening, test deletion, lint disable, scope creep).
- Per-agent standards file emit via `--init-agent-standards`. Targets:
  `codex`, `claude-code`, `cursor`, `copilot`, `windsurf`, `generic`.
- Invokable skill bundle at `skills/secure-code-agent/` (Anthropic-format
  SKILL.md + Codex + Copilot adapters) — portable across Claude Code,
  Codex, and Copilot Chat.
- Comprehensive docs: design, standards anchors, scoring math, scanner
  caveats, remediation rationale, threat model.

### Known limitations
- No CodeQL invocation — CodeQL runs in GitHub-hosted analysis; we ingest
  its SARIF artifact via `--sarif-import`.
- Tier-2 scanners (Trivy, Checkov, Hadolint, OSV-Scanner, OpenSSF Scorecard)
  have protocol stubs but no full implementation in v0.1 — tracked for v0.2.
- No language coverage beyond what Tier-1 scanners support (Python, JS/TS).
  Go / Java / Rust / Ruby scanners (gosec, SpotBugs, Brakeman) tracked for v0.3.
