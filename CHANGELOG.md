# Changelog

All notable changes to `secure-code-agent` are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/). Semver pre-1.0 — config
schema may evolve.

## 0.4.0 — 2026-09-09

All eight v0.3.0 release blockers are closed, and so are the four structural
problems the architecture audit ranked
([`architecture.md`](docs/architecture.md) §2, §3, §4). Two decisions remain
open on purpose and are named at the foot of this section.

### Changed — behaviour that will move existing results

Pre-1.0, and these are corrections rather than features, but a repository
audited with 0.3.0 can score differently under 0.4.0:

- **Findings from paths matching `paths.exclude_patterns` no longer appear.**
  They did for ten of fifteen scanners, while the same patterns already
  excluded those files from the LOC denominator — so scores were computed with
  a numerator and a denominator measuring different repositories. Expect fewer
  findings and, in repositories with large excluded trees, a different score.
- **The markdown report and PR comment now withhold a grade** whenever the JSON
  does. If you have no `gates.require_scanners` declared, output that used to
  read `Score: … A+` now reads `Finding score (not a verified grade)`. Declare
  the scanner set to get a verified grade back.
- **`Scanner.run()` is now `Scanner.scan()` and returns a `ScanResult`.** This
  breaks any out-of-tree scanner adapter. Nothing in the documented CLI or
  config surface changes; see [D13](docs/decisions.md) for the migration shape.

### Added

- The offline Semgrep ruleset is now a **versioned profile**: `sca-offline`,
  with a version and a SHA-256 digest of the shipped file, cited in scanner
  provenance as `sca-offline@1.1.0 (digest…)`. A finding can name the rules
  that produced it and be re-checked against the same baseline. The digest is
  evidence where the version is only an assertion — editing the ruleset inside
  an installed wheel leaves the version unchanged and the digest does not. See
  [D10](docs/decisions.md).
- The profile is **20 rules across 5 languages** — JavaScript/TypeScript, Go,
  Ruby, Java, and the two Python patterns Bandit measurably misses. Every rule
  declares a CWE, an OWASP bucket, a confidence and a version, and every rule
  is paired-tested: a fixture it must flag and a fixture it must not. Proving a
  rule fires is the easy half. A dedicated CI job runs both, because these
  tests skip where Semgrep is absent and a skip nobody notices is how a ruleset
  rots.
- **The profile covers the languages the floor cannot read offline, not Python.**
  An intermediate revision carried 19 Python rules; measured against Bandit, 17
  of them duplicated it. Bandit is in the floor, is Apache-2.0, and is already
  offline — so the "offline coverage" argument that justified them was simply
  wrong, and `CONTRIBUTING.md` has forbidden a parallel ruleset since the first
  commit. Enforced by `test_no_python_rule_duplicates_bandit`. See
  [D11](docs/decisions.md).

  That entry originally continued *"nothing in the floor reads JavaScript, Go,
  Ruby or Java without the network"*. It was asserted without running any of
  those tools, and two of them existed — see D12 below, which is the same
  mistake caught a second time and is why the coverage check is now automated
  per language.
- `product-intent.md` §5 principle 2 amended. It read as an unqualified refusal
  to author rules, which we already violated twice over. The bound that
  replaces it: our ruleset is the offline floor, not a competitor — language
  primitives in, framework rules out, enforced by a test rather than by review.
  See [D9](docs/decisions.md).

### Added — the coverage check, and the tools it found

- **The floor gained njsscan and RuboCop, and gosec as opt-in.** D11 shrank the
  Python rules against Bandit, then justified the remaining twenty-one with a
  sentence nobody tested. Running the check found that njsscan (LGPL-3.0+)
  covers Node's md5, sha1, `Math.random` and the
  `NODE_TLS_REJECT_UNAUTHORIZED` form, and RuboCop's Security cops (MIT) cover
  Ruby's `eval`, `Marshal.load` and `YAML.load` — both offline, both clean on
  the negative fixtures. Three rules were deleted and two narrowed to the half
  the tool leaves. See [D12](docs/decisions.md).
- **The gaps that remain are measured, not assumed.** njsscan's exec/eval/DOM-XSS
  rules are taint rules gated on an Express `(req, res)` handler shape, so they
  are silent in a CLI script or a Lambda handler. gosec loads packages through
  `go list` and cannot read Go without the toolchain — the boundary MA's
  ADR-012 draws for SpotBugs, and why it is opt-in rather than floor. PMD's
  entire Java security category is two rules, neither of them ours.
- **Adapters now return a `ScanResult`** stating what happened, rather than
  signalling it by naming a finding. `classify_execution` is deleted, not
  deprecated. See [D13](docs/decisions.md).
- **Parsers are tested against real captured scanner output**, not against
  hand-written mocks — six tools captured, the other nine declared in
  `SCANNERS_WITHOUT_A_REAL_CAPTURE` with reasons. Plus
  `tests/integration/test_scoring_drift.py`, which `CONTRIBUTING.md` had cited
  for far longer than it existed. See [D14](docs/decisions.md).

### Fixed — defects found by the tool auditing itself

- **`paths.exclude_patterns` was honoured by five of fifteen adapters.** The
  rest have no flag for it, and nothing filtered centrally — so a config
  excluding `tests/` still reported findings from deliberately-vulnerable
  fixtures. Worse, `exclude_patterns` is also the LOC denominator, so findings
  from excluded paths were scored against lines that were never counted.
  Enforced once now, after collection, for every adapter and every SARIF import
  alike. Control findings are exempt, or a failed scanner would go silent.
- **Every tagged release would have failed at its own preflight.** The release
  workflow installed `.[dev,required-scanners]` while the config requires the
  floor, leaving checkov, osv-scanner, trivy, semgrep and gitleaks unresolved.
  The floor install now lives in one composite action both workflows use.
- **Reports named a clean category as the worst one.** `min()` over the grade
  dict returns the first key in enum order on a tie, and every category grades
  5.0 when nothing counts against it — so an all-informational finding set
  reported *"worst category: secrets"* on a repository with zero secrets
  findings. It is `None` when nothing graded below the ceiling, and ties break
  by finding count rather than enum order.
- **The markdown report and PR comment claimed grades the JSON withheld.**
  `Verdict` decides once whether a run can claim a verified grade, but two
  renderers were never wired to it and kept a weaker condition, so a run with
  no `gates.require_scanners` printed a bare **A+** in the two artifacts people
  actually read while the JSON reported `verified_grade: null`.
- **The JSON report was the one output missing from `.gitignore`.**

### Fixed — remaining known defects

- The default `secure-code-agent.json` is read from the **audited project**,
  not the shell's working directory. The config was loaded before the target
  was resolved, so auditing another tree from this repository applied *this*
  repository's required scanners to it, and a tree carrying its own policy was
  audited without it. Release-blockers §7.
- The emitted SARIF `$schema` pointed at an `oasis-tcs` raw path that returns
  404. It now uses the OASIS canonical URL, which returns 200 — both were
  checked rather than assumed. The documents always validated; only the
  locator a consumer would follow was broken. Release-blockers §8.
- The release-blocker checklist listed every item twice, once ticked and once
  not, from a keep-both conflict resolution during a rebase. A checklist that
  says an item is both done and not done is worse than no checklist.

### Security

- **Repository-supplied configuration can no longer choose what the host
  executes.** `scanners.<name>.command` accepted a relative path, resolved it
  under the audit target, and ran it — so a repository shipping its own
  `secure-code-agent.json` selected the auditing host's executable. That is
  threat model T1, realised by the tool. A config found inside the tree may no
  longer name a command that also resolves inside the tree; the scanner reports
  `unavailable`, which fails required coverage. A config kept outside the tree
  is an operator artifact and keeps the documented tree-local interpreter
  workflow. `--trust-target-config` is the explicit opt-in, and is
  command-line-only so a config cannot grant itself the trust. See
  [D1](docs/decisions.md).
- The containment check applies to the resolved path from every resolution
  route, not only the relative-path branch, because `PATH` can contain `.` or a
  tree-local directory.

### Fixed

- **Withholding evidence can no longer buy a better grade.** The score is a
  rate over findings, so disabling scanners removed findings and the number
  rose — on one tree, from 0.00/F to 5.00/A+, the best possible letter earned
  by looking less hard. Scanner coverage did not catch it, because a disabled
  scanner produces no execution record at all. A letter grade is now issued
  only when `gates.require_scanners` declares a scanner set *and* coverage
  confirms it ran; otherwise `verified_grade` is null with reasons. The numeric
  estimate is unchanged and still reported — it is honest about what was found,
  it simply is not a grade. Borrowed from `maintainability-agent`'s P3 and
  ADR 001.
- The decision to qualify or withhold a score is made once, in
  `scoring.verdict()`, instead of independently in five renderers — the
  duplication `architecture.md` §3 recorded, where the SARIF site was missed on
  the first pass.
- Unknown top-level configuration keys are rejected instead of ignored. The
  schema declared `additionalProperties: false` while the loader accepted
  anything, so a typo'd gate name silently disabled a gate. See
  [D2](docs/decisions.md).

### Documentation

- [`docs/decisions.md`](docs/decisions.md) — a decision register, recording the
  trust ruling and the three integration decisions taken for the
  `maintainability-agent` Security pillar.

### Still open, deliberately

Neither is a defect, and neither can be settled by a refactor — both are about
whether the number this tool reports means anything.

- **The condition scale is uncalibrated** ([D5](docs/decisions.md)). The bands
  were borrowed from `maintainability-agent` without its calibration study, and
  the `sqrt(LOC/1000)` dampener is an invented normalizer with no corpus behind
  it. `tests/integration/test_scoring_drift.py` pins the scale's *stability*;
  nobody has established that A+ corresponds to anything real. Treat the letter
  as a relative signal, not an absolute one.
- **The score's null state is still "perfect"**
  ([`architecture.md`](docs/architecture.md) §5). A repository nothing could be
  scanned in produces zero findings and therefore A+. That is why coverage
  exists as a separate axis and why a verified grade is withheld without a
  declared scanner set — but it still asks a reader to combine two numbers.
  Whether the deliverable should be a single verdict is a product decision.

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
- `--fail-on-gate` is refused when no gate is configured. Previously an audit
  could detect a HIGH CWE-78 finding, score it 0.00/F, report it in full, and
  still exit 0, because every gate was absent and an absent gate does not trip.
  A gate key that is present but inert — an empty severity list, an empty cap
  map, a `min_score` of 0 — does not count as configured. Report-only audits
  without `--fail-on-gate` are unaffected.
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
