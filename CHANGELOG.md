# Changelog

All notable changes to `secure-code-agent` are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/). Semver pre-1.0 — config
schema may evolve.

## 0.8.0 — unreleased

### Fixed — "gate PASS" was printed when no gate existed

Out of the box, with no configuration, a 200,000-line repository containing
SQL injection, `shell=True` command injection, `pickle.loads`, MD5 and
`eval` reported:

```
score 4.06 — grade withheld (A- unverified)  ·  gate PASS
```

Every word is technically defensible. The grade *was* withheld. No gate
tripped, because `DEFAULT gates` is `{}` and an absent gate cannot trip. And
the line still tells a reader their repository is fine. The work order was
correct at the same moment — seven findings in §FIX, the SQL injection and
the `shell=True` among them — so the first-class output worked and the
summary undid it.

Three states now, where there were two:

```
gate FAIL            — a configured gate tripped
gate PASS            — a configured gate held
gate NOT CONFIGURED  — nothing was checked
```

An unconfigured run says so in words and points at the work order.
`gate.configured` and `gate.enforced` are in the JSON report for consumers
that read `passed` as a security signal.

**`passed` is unchanged.** No gate tripped, which is true, and flipping it
would fail every ungated CI job that exits 0 today — a behaviour change
hiding inside a reporting fix. Inert configuration is still not enforcement:
an empty `fail_on_severity` list and a `min_score` of 0 both read NOT
CONFIGURED.

### Recorded — D15: a scanner's severity is not a measure of consequence

Four problems solved or attempted on this project turned out to be one
problem: the score grading Bandit's talkativeness, `B105` scoring 0 useful
hits in 22, a proposed severity floor, and proposed default gates.

A scanner's severity answers *"how confident am I that this pattern is
present"*, not *"how bad is this in your code"* — Bandit rates SQL injection
**medium** and `hashlib.md5` **high**. Six candidate floor rules were
measured against the corpus and four known-vulnerable controls; none
separates. Two candidate default gates likewise: `critical`-only catches
none of four vulnerable controls, `critical`+`high` fails five of ten
well-maintained repositories.

Severity remains a weight in the score and a filter an operator configures.
Nothing may use it to *identify* the dangerous findings. The full data is in
[`docs/decisions.md`](docs/decisions.md) D15, including the one mechanism
measured to work — `fail_on_new`, which ignores severity entirely and
therefore does not inherit the flaw.

## 0.7.0 — 2026-09-11

Nine defects, all found by running the tool against repository shapes and
content the calibration corpus does not contain. Every one survived 526
tests and a clean self-audit.

### Fixed — targets that are not a tidy repository full of code

- A **mistyped path** reached the scanners and died with a raw
  `FileNotFoundError` out of `subprocess.py`. The scan root is checked
  first, and the error names the path.
- **A single file as the target** crashed twice: every adapter passed it as
  a subprocess `cwd`, and `find_repo_root` returned the *file* when no git
  repository sat above it, so the report path became
  `one.py/secure-code-report.md`. `secure-code-agent one_file.py` is the
  first thing anyone tries and it was always meant to work.
- **A single file measured zero lines**, because `rglob` on a file yields
  nothing. A zero denominator is not normalised at all, so the grade became
  the raw subtotal — a two-line file containing `eval(input())` scored
  3.59 (B+) instead of 0.00 (F).

### Fixed — the corroboration merge was hiding findings

Bandit files `B602` (`shell=True`), `B603` (subprocess call) and `B607`
(partial executable path) all under CWE-78. Keying the merge on the CWE
collapsed them, so `subprocess.call('ls', shell=True)` reported `B607`
alone with the `shell=True` buried inside it as a footnote — the more
serious of the two, missing from the work order.

A shared CWE is no longer sufficient. Two rules from the *same* scanner
merge only through the hand-checked alias table; different scanners still
merge on a shared CWE, which is the cross-tool corroboration the function
exists for.

`test_two_different_weaknesses_at_one_line_stay_two_findings` has asserted
this since the merge was written and passed throughout, because its
fixtures carried no CWE. Reading Bandit's CWEs in 0.6.0 gave them one and
turned a real test into a false assurance.

### Fixed — a category nothing could read was graded 5.0

A `Dockerfile` with `USER root` and `chmod 777`, beside Terraform with a
`public-read` bucket and a 0.0.0.0/0 ingress rule, scored **config_iac
5.0** with neither checkov nor hadolint installed.

A hand-written list claimed `builtin_rules` covered `secrets` and
`config_iac` — it has never had a rule for either — and omitted
`supply_chain`, which it does cover. The set is derived from the standards
map now, so it cannot drift from the rules it describes.

### Fixed — Terraform lines were not counted

checkov is in the floor and reads `.tf`, so its findings were scored
against a denominator that excluded every file it had read. `.tf` and
`.tfvars` join `DEFAULT_INCLUDE_EXTS`.

### Fixed — SARIF raised thousands of alerts for test fixtures

SARIF is consumed by code-scanning platforms that turn each result into an
alert, and `suppressions` is the field they honour. We wrote
`properties.suppressed` instead — a field of our own invention no consumer
reads. So findings the operator had explicitly suppressed in
`.scignore.yaml` still became alerts, and so did every test-tree and
documentation finding.

On a large real repository that was **4,929 results of which 4,847 were
test fixtures** — 4,847 alerts for deliberately-vulnerable test data,
burying 82 findings in the shipped source. The same audit now raises 82.
Suppressed, not omitted: every finding stays in the document with its
location, axis and justification.

### Fixed — semgrep resolved but did not run

Semgrep deprecated `python -m semgrep` in 1.38.0: it prints a notice, exits
0, and analyses nothing. The adapter declared that fallback, which fires
whenever the module is importable but the binary is off PATH — the normal
state after installing njsscan, which pulls semgrep in as a dependency.

Coverage caught it, so no grade was ever claimed on a scanner that had not
run, but it reported "semgrep failed" to operators whose situation was
"semgrep is not on PATH". bandit, njsscan, checkov and pip-audit all still
run correctly under `python -m` and keep the fallback; a test now asserts
any declared `python_module` actually exposes a `__main__`.

### Known, measured, not changed

A repository with large checked-in JSON artifacts scores better for having
them: the same tree measured A- (4.02) with 879k lines of generated reports
counted and D (1.57) without. `docs/scoring.md` defines LOC as "scanned
code volume", which those lines are not. The fix is the same open question
as the `sqrt(LOC)` size bias — what the denominator should measure — and is
recorded rather than guessed at.

## 0.6.0 — 2026-09-11

### Work orders are the first-class output

The remediation prompt is now **written on every run**, alongside the report.
`_resolve_outputs` read config for the report and nothing at all for the
prompt, so the artifact that grades your code was always written and the
artifact that fixes it needed `--prompt-output`. `prompt_path` had been
declared in `DEFAULT_OUTPUTS` the whole time and the resolver never read it;
four of six keys were dead the same way. Set any `outputs.*_path` to `null`
to disable one — which the loader used to reject despite the docstring
promising it.

Findings are **tiered**: `§FIX` (patch it), `§REVIEW` (confirm first, reason
stated per finding), `§ACCEPT` (test tree and documentation — propose a
suppression, do not patch). A flat list gave a `shell=True` command
injection and a `PASSWORD_FIELD = "password"` name-match identical billing.

A noisy rule is demoted, never dropped. Bandit's `B105` produced zero useful
hits out of 22 across the calibration corpus and still caught a planted
hardcoded credential, so the matched *value* is judged as well as the rule.

Work-order paths are repository-relative. `§ACCEPT` is summarised by rule
with a drafted suppression, and `§FIX`/`§REVIEW` cap at 40 blocks and say
what they left out — auditing this repository produced a 541KB,
15,390-line work order before that, now 4.8KB and 111 lines.

### New — `--verify-against`, proving the work order helped

```bash
secure-code-agent . --verify-against secure-code-report.json
```

Re-audits and reports what was fixed, what is still open, what was
**silenced rather than repaired**, and what this work introduced. Exits
nonzero unless the run passes.

Silencing is the case worth having. **Lint disable** has been in the
README's anti-pattern table since the first commit and hard constraint 6
forbids it; forbidding is not detecting. Bandit honours `# nosec` itself, so
a silenced finding stops arriving and reads as repaired. The source is now
read back around the reported line.

Test-tree and documentation findings are reported but never required, since
`§ACCEPT` tells the agent not to patch them.

### New — scan history and trend

Every run appends one line to `.secure-code/history.jsonl` and prints the
movement: `3.90 (B+) — up 3.86 from 0.04 (F), 3 scored runs`. Append-only; a
malformed line costs one run rather than the history. A run too thinly
covered to grade records `null` and is skipped rather than plotted as a
collapse to zero.

### Changed — repeats of one rule saturate

**This moves scores.** Sorted worst-first, a rule's k-th hit now counts
`weight / sqrt(k)`. One rule firing 56 times is one fact observed 56 times,
not 56 independent defects; distinct rules still add in full.

Grading Django, FastAPI, httpx and Flask all F was measuring how talkative
Bandit is on large Python codebases. Django's "hardcoded passwords" are
`EMAIL_HOST_PASSWORD = ""` and `SECRET_KEY = ""`; its "SQL injection" hits
include an `ImproperlyConfigured` error message and a parameterised
`cursor.execute`. Corpus effect: httpx 0.13 F → 2.58 B−, fastapi 0.00 F →
2.47 C, requests 2.54 → 3.98 B+. No repository scored lower.

### Fixed — 86% of findings carried no CWE

Bandit publishes a CWE for every plugin and gosec for every rule, and both
were discarded — gosec went as far as formatting its CWE into the message
text and never setting `canonical_cwe`, so scoring, the Top-25 multiplier
and the SARIF taxonomy all saw nothing. Corpus CWE coverage 14% → **100%**;
OWASP is derived from the CWE where the curated map is silent, reaching 62%,
and stays null where the standard has no category rather than being invented.

### Fixed — `exclude_patterns` never applied to gitleaks findings

gitleaks reports repository-relative paths and every other scanner reports
absolute ones. Every consumer that asked "where is this?" resolved a
relative path against the *process working directory*, so the answer came
back "not excluded" — silently, and fail-open. Four `tests/certs/*.key`
files held `requests` at F and six documentation examples held `flask`
there. Paths are now anchored at the one constructor every adapter passes
through.

Separately, `**/` did not match at depth zero, so `**/*_test.go` never
matched a root-level `context_test.go`.

### Fixed — gitleaks could not see the working tree

`detect --source` scans commits only, so a plaintext key sitting
uncommitted produced "no leaks found". Both `gitleaks dir` and `gitleaks
git` now run; the overlap merges.

### Fixed — the tool audited its own output

`secure-code-report.md` lands in the audited tree and the next run scanned
it, finding a "secret" at line 11,529 of its own report. Two identical
audits of an unchanged repository returned 0.00 and 4.25. The run now drops
the paths it is about to write — and their lines — from both its findings
and its LOC denominator.

### Fixed — other

- `B308`/`B703` are the same Bandit check under two ids and were counted
  twice; `merge_corroborating` collapses them and records the second
  sighting rather than discarding it.
- `sca.offline.ruby.code-injection` matched `class_eval(&block)`, Ruby's
  *safe* form. Offline profile bumped to `sca-offline@1.2.0`, and the
  ruleset digest is now pinned to the profile version.
- A suppressed finding was republished as `axis: primary, scored: true`.
- A finding that tripped the gate could be absent from the report, and
  side-axis findings could never be baselined.
- Scanner versions were recorded as ANSI escape sequences when a tool
  colourised `--version` (njsscan read as `[34m`).

### Calibration — the study was measuring the wrong population

Six of fourteen corpus repositories scored near-perfectly because nobody had
looked at them: Python produced 712–5,107 real findings each, everything
else 0–4. `njsscan` and `rubocop` were not installed; Go and Java cannot be
read by this floor at all (D12). The four unreadable repositories had their
own median of **5.00** and were holding the corpus median up.

The study now reports the distribution over repositories a language scanner
actually read — **examined median 3.38, in the B band, which is the
target** — and names what it excluded. No band edge needed moving.

`njsscan` and `rubocop` are required for a valid calibration run.

## 0.5.0 — 2026-09-10

### Fixed — 0.4.0 reports itself as 0.3.0

`__version__` was a literal in `src/secure_code_audit/__init__.py` and the
version was *also* a literal in `pyproject.toml`. They drifted: pyproject moved
to 0.4.0 and the package did not.

**The released 0.4.0 wheel on PyPI contains `__version__ = "0.3.0"`.** Verified
by downloading it. Every artifact that build produces names the wrong producer:
SARIF `tool.driver.version`, the JSON report's `version`, the Markdown report
header, `--version`, and `security-pillar.json`'s `producer.version`.

The release workflow verified the tag against *pyproject's* line and never read
the package, so it checked the half that was right and shipped the half that
was wrong.

PyPI is immutable, so **0.4.0 stays wrong**. If you have artifacts produced by
0.4.0, their producer version is understated by one release. Upgrade to 0.5.0,
which is the first build whose artifacts name themselves correctly.

The fix removes the duplication rather than policing it. `pyproject.toml` now
declares `dynamic = ["version"]` and reads
`secure_code_audit.__version__`, so there is one literal and the two cannot
disagree. The release workflow reads the package. A first attempt used
`importlib.metadata` instead and was worse — it reports whatever distribution
happens to be installed, which in a working checkout was a stale 0.1.0, and
provenance that depends on the reader's install state is not provenance.

### Added

- **`--security-pillar <path>`** emits `security-pillar.json` for
  `maintainability-agent` to ingest ([D3](docs/decisions.md), contract in
  [`docs/ma-integration.md`](docs/ma-integration.md)). Carries a practice level
  read from configuration and CI beside a code condition read from the
  scanners, as two values that are never averaged. `condition` is `null`
  whenever coverage is incomplete. Standalone use is unaffected.
- **Dependency findings move to their own reported axis**, still gated. A CVE
  in a pinned dependency is fixed with a version bump; an injection flaw is
  fixed with a rewrite. Measured as the largest remaining scoring distortion
  after the test tree — median `worst_normalized` 15.36 against 7.32.
- `maintainability-agent`'s **P1–P8 promise table** adopted into
  [`product-intent.md`](docs/product-intent.md), with P6 recorded as currently
  unmet because the calibration study ran Semgrep online.

## 0.4.0 — 2026-09-09

> **Correction.** This build reports itself as `0.3.0` in every artifact it
> produces — see 0.5.0 above. The release is otherwise as described; only the
> producer version is wrong, and PyPI cannot be amended in place.

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
