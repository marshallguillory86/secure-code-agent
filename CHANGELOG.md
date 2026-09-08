# Changelog

All notable changes to `secure-code-agent` are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/). Semver pre-1.0 — config
schema may evolve.

## 0.3.0 — 2026-08-09

Coverage-integrity release. A clean finding set and successful scanner
coverage are now reported and gated separately.

### Added

- Enforced `gates.require_scanners`. Required scanners now fail coverage when
  unavailable, timed out, failed, emitted invalid output, were not applicable,
  or were excluded from the selected scan.
- Structured scanner provenance in Markdown and JSON reports: outcome,
  resolved command, reported version, finding count, and failure reason.
- Explicit per-scanner `command` configuration with safe `shell=False`
  execution, relative-path resolution from the target, `PATH` lookup, and
  Python module fallback for Bandit, pip-audit, Semgrep, and Checkov.
- pip-audit input modes for recursively discovered or explicit requirements,
  `pyproject.toml` projects, locked projects, and configured environments.
- Focused regression tests for coverage gates, CLI exit behavior, executable
  resolution, pyproject auditing, lock mode, and invalid scanner output.
- PyYAML as an explicit bounded runtime dependency so the advertised
  `.scignore.yaml` security control works in clean installations.
- A pinned `required-scanners` extra and composite-action installation path
  for Bandit 1.9.4 and pip-audit 2.10.1.
- A minimal pinned self-audit input for the package's supported runtime
  dependency floor, isolated from unrelated CI and development tools.
- Tag releases re-run lint, formatting, branch coverage, and required scanner
  coverage before attestation or publication.
- `--preflight` resolves enabled scanners and reports each one's command,
  version, and install remedy without running an audit, exiting nonzero when a
  required scanner is unavailable or not enabled.
- Per-scanner install guidance, surfaced in unavailable findings and preflight
  output. The agent still installs nothing itself; acquisition stays with the
  operator's package manager or a pinned CI action.
- A `python-scanners` extra for Semgrep and Checkov, and `required-scanners`
  folded into `dev` so a fresh checkout can run its own audit.
- Imported SARIF now counts as scanner coverage and can satisfy
  `gates.require_scanners`, which is the supported way to gate on scanners that
  ship as standalone binaries. `--sarif-import NAME=PATH` names a run whose
  SARIF driver name does not match its configured id.
- An install matrix in `docs/scanners.md` and a development setup section in
  `CONTRIBUTING.md`.
- An exact Ruff pin and a Markdown exclusion, so `ruff format --check` is
  reproducible. Ruff 0.16 began formatting Python blocks embedded in Markdown;
  with an unpinned formatter that turned an upstream release into a red build
  with no change in this repository.

### Fixed

- CI now uploads the audit SARIF to Code Scanning when required coverage fails.
  The step carried no status-check function, so GitHub's implicit `success()`
  skipped it exactly when the SARIF reported `executionSuccessful: false`,
  leaving the Security tab showing an older clean result.
- Gitleaks and TruffleHog no longer record a clean scan after signalling
  findings. Gitleaks exit 1 with an empty or non-array report, and TruffleHog
  exit 183 with empty output, previously returned zero findings and classified
  as a completed scan — discarding the scanner's own assertion that it found
  secrets, in the highest-weighted category. Both now fail coverage. A clean
  exit with no output remains a clean scan.
- `scanners.semgrep.online: false` now genuinely runs offline. It selected
  `p/security-audit` and described it as a bundled ruleset; that is a Semgrep
  Registry pack fetched over the network, so an air-gapped run failed on a
  certificate error while the config claimed offline coverage. A ten-rule
  ruleset now ships in the wheel and is used instead, with a `tool_error` if it
  is missing rather than a fallback that reaches the network. It is narrower
  than the Registry packs and `docs/scanners.md` says so.
- Semgrep findings now carry a CWE. Semgrep folds `metadata.cwe` into
  `properties.tags` rather than `properties.cwe`, which the adapter alone read,
  so every Semgrep finding — Registry rules included — arrived unmapped and
  scored without CWE Top-25 weighting.
- Semgrep runs with `--no-rewrite-rule-ids`. Semgrep otherwise prefixes rule
  ids with the config file's path, which varies by install location and would
  destabilize baseline fingerprints across machines.
- Scanner timeouts, unexpected exits, missing output, and parse failures no
  longer silently look like successful clean scans in the updated adapters.
- Unreadable, malformed, or run-less `--sarif-import` input previously ingested
  zero findings with no warning and no coverage signal; it now fails the gate.
  An import that reports its own `executionSuccessful: false` is recorded as a
  failed execution rather than laundered into a clean result.
- Imported SARIF is now recorded as `unverified` rather than `completed`. We
  never observed the process, so a successful import means the operator vouched
  for the artifact, not that we watched it succeed — `executionSuccessful: true`
  is a file describing itself. Unverified coverage still satisfies
  `require_scanners` and does not degrade status to `PARTIAL`, but is named in
  every output: the terminal summary, `coverage.unverified` in JSON, and
  `unverifiedScanners` in the emitted SARIF. A local run outranks an import of
  the same scanner.
- Structurally malformed imported SARIF is contained as failed coverage instead
  of raising an uncaught `AttributeError`. A non-object run or a non-array
  `results` fails that run and still emits the full evidence set; non-object
  entries inside a valid `results` array are skipped rather than discarding the
  scanner's other findings.
- A scanner reported both by local execution and by SARIF import now resolves
  to its worst outcome, so a clean import cannot mask a failed local run.
- CLI `--fail-on-new` now ignores informational control findings consistently
  with configured `gates.fail_on_new`.
- Unknown configured or required scanner names fail configuration validation.
- The composite GitHub Action installs its own checked-out source instead of
  an unrelated latest PyPI release and now emits its advertised JSON report.
- `--changed-only` now fails explicitly instead of silently running an
  unscoped audit; safe changed-file orchestration remains future work.
- Multiple positional scan roots now fail explicitly instead of scanning only
  the first root and overstating coverage.
- The inert `asvs_level` setting is now rejected and removed from the schema;
  this release does not claim an ASVS-level gate.

### Documentation

- Corrected pip-audit project invocation, baseline approval, scanner network,
  cross-scanner deduplication, report escaping, and release-provenance claims
  so documented guarantees match executable behavior.

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
  pip-audit + npm-audit by design; stable fingerprints support baseline
  matching, but this release did not yet deduplicate scores across scanners.
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
- SARIF 2.1.0 emit + ingest. External SARIF (CodeQL, Snyk, Trivy, etc.) is
  combined with locally-run findings; identical findings are not collapsed.
- Standards taxonomy: mapped findings include a CWE id used in stable
  fingerprints, plus an OWASP Top
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
