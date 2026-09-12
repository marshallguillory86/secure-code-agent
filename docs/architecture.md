# secure-code-agent — Architecture Audit

> Status: **v0.12.0 — 2026-09-11.** Assessment of the system as built.
> Companion docs: [`design.md`](design.md) states the intended architecture;
> this document records where the implementation diverges from it and which
> divergences are generating recurring defects.

## 0. Verdict

**The core architecture is sound. Do not rewrite it.**

The central abstraction — every scanner normalizes to one frozen `Finding`, and
everything downstream reads that single type — is correct and has held up
across twelve adapters and five output formats. The v0.3.0 separation of
*scanner coverage* from *findings* is a real architectural improvement, not a
patch.

Three structural choices, however, account for most of the defects found in
recent review cycles. They are listed in §2–§4 in the order they should be
addressed. Until they change, the same shapes of bug will keep recurring,
because each one makes a class of error undetectable at author time.

## 1. What is load-bearing and correct

Keep these. They are the reason the system is worth repairing rather than
replacing.

1. **`Finding` as the lingua franca** ([`findings.py`](../src/secure_code_audit/findings.py)).
   A frozen dataclass with a stable fingerprint, produced by every adapter and
   consumed by every renderer. Fingerprints hash canonical CWE (falling back to
   rule id), POSIX-normalized path, and whitespace-collapsed evidence, so a
   reformat-only edit does not break baseline identity.

2. **Adapters must not raise.** `Scanner.run()` converts every failure into a
   finding rather than an exception. One broken scanner cannot kill the audit.
   Correct failure isolation for an orchestrator.

3. **Coverage as a second axis**
   ([`scanner_status.py`](../src/secure_code_audit/scanner_status.py)). "Did the
   tool run" genuinely is orthogonal to "what did it find," and modelling it
   separately is what stopped a clean finding set from implying a complete
   audit.

4. **Suppressions with mandatory expiry.** A required `expires` date, a 365-day
   cap, and expired entries becoming CRITICAL findings
   ([`suppressions.py`](../src/secure_code_audit/suppressions.py)). Most tools
   let suppressions rot indefinitely. This design is better than most
   commercial equivalents and should be protected in any refactor.

5. **`scoring.py`.** Pure functions, no I/O, per-gate evaluators split
   deliberately to hold cognitive complexity under the standard this project
   ships. The best-factored module in the repository.

6. **Subprocess discipline** ([`scanners/base.py`](../src/secure_code_audit/scanners/base.py)).
   Argument arrays, `shell=False`, sanitized environment, explicit
   `allowed_exits`. No shell interpolation anywhere in the scanner path.

## 2. Problem 1 — scanner outcomes are encoded in strings

**Severity: high. Fix first. — CLOSED 2026-09-09, see D13.**

An adapter signals what happened to it by *naming a finding*:

```python
rule_id=f"{self.name}.tool_unavailable"     # → ScannerOutcome.UNAVAILABLE
rule_id=f"{self.name}.tool_timeout"         # → ScannerOutcome.TIMED_OUT
rule_id=f"{self.name}.tool_error"           # → ScannerOutcome.FAILED
rule_id=f"{self.name}.parse_error"          # → ScannerOutcome.FAILED
rule_id=f"{self.name}.no_dependency_input"  # → ScannerOutcome.NOT_APPLICABLE
```

`classify_execution` then reverse-engineers intent by prefix matching
([`scanner_status.py:63`](../src/secure_code_audit/scanner_status.py#L63),
[`:82`](../src/secure_code_audit/scanner_status.py#L82)), and counts real
findings by *exclusion*
([`:96-97`](../src/secure_code_audit/scanner_status.py#L96-L97)):

```python
security_findings = sum(
    1 for finding in findings if not finding.rule_id.startswith(f"{name}.tool_")
)
```

### Why this generates defects

Nothing enforces the protocol. No type, no test, no lint. An adapter that names
a control finding incorrectly silently becomes a security finding; one that
happens to emit a rule starting `no_` becomes a false `NOT_APPLICABLE`, which a
required-scanner gate then escalates into a hard failure. The convention is
documented only by example, and the twelve adapters were written at three
different times.

The same missing abstraction shows up in
[`cli.py:488`](../src/secure_code_audit/cli.py#L488), where the orchestrator
special-cases a single scanner by name because there is nowhere on the adapter
to declare its own audit scope:

```python
def _scanner_scope(name: str, cfg: ScannerConfig) -> str | None:
    if name != "pip_audit":
        return None
```

### Fix

Adapters return a structured result rather than smuggling outcome through
`rule_id`:

```python
@dataclass(frozen=True)
class ScanResult:
    outcome: ScannerOutcome
    findings: list[Finding]
    reason: str | None = None
    scope: str | None = None
```

`classify_execution` stops parsing strings and becomes a trivial mapping.
Control findings become a *rendering* concern derived from the outcome, rather
than the source of truth for it. Scope moves onto the adapter, deleting the
name check in the orchestrator.

Estimated cost: one focused session across twelve adapters. This is a
prerequisite for cleanly fixing §3.

**Done.** All fifteen adapters return `ScanResult`; the outcome constructors
live on `Scanner` so the control finding is derived from the outcome rather
than being the thing an outcome is inferred from. `classify_execution` is
deleted — not deprecated — because a working string-parser left in the tree is
an invitation to wire the next adapter into it. `_scanner_scope`'s name check
is gone: adapters answer `scope()` for themselves. `tests/unit/test_scan_protocol.py`
is the lint that blocks the class, including an AST check that fails any
adapter hand-building a control finding.

Two live defects fell out of the migration. `trufflehog` and `npm_audit` could
return real findings *alongside* a control finding; the old classifier's early
return then recorded `finding_count=0` for a run whose findings did reach the
report, so the count and the report disagreed. And `pip_audit._parse` returned
a control finding from a parsing helper, which made a leaf function the thing
that decided the run's outcome. Both are structurally impossible now.

## 3. Problem 2 — every contract has two or more sources of truth

**Severity: high. Fix second.**

The same failure mode appears in four places. In each case a contract is
written down more than once, with no mechanism keeping the copies in sync, and
in each case the copies have already drifted.

| Contract | Sources of truth | Observed drift |
| --- | --- | --- |
| Config shape | [`config.py:99-118`](../src/secure_code_audit/config.py#L99-L118) hand validation (264 lines) **and** `secure-code-agent.schema.json`, not connected at runtime | The schema rejected its own `$schema` key; `require_scanners` minimum had to be enforced separately in both |
| Score qualification when coverage is incomplete | Five sites: [`cli.py:453`](../src/secure_code_audit/cli.py#L453), [`renderers.py:35`](../src/secure_code_audit/renderers.py#L35), [`:169`](../src/secure_code_audit/renderers.py#L169), [`:348`](../src/secure_code_audit/renderers.py#L348), [`sarif.py:69`](../src/secure_code_audit/sarif.py#L69) | Each was implemented separately; the SARIF site was missed entirely on the first pass |
| Agent guidance | `instructions.py::_BODY`, `skills/secure-code-agent/SKILL.md`, `skills/secure-code-agent/copilot/*.prompt.md`, `skills/secure-code-agent/agents/*.yaml`, `README.md`, `docs/` | The `--changed-only` deprecation updated four locations and missed two, leaving shipped agent instructions recommending a flag that exits 2 |
| Packaging | `pyproject.toml` `package-data` globs **and** the directory actually existing | The globs once matched nothing at all; now `test_the_offline_ruleset_is_declared_as_package_data` fails if a shipped data file is not matched by one |

### Fix

One source each.

- **Config:** generate `secure-code-agent.schema.json` from the config
  dataclasses as a build/test step, and assert in CI that the committed schema
  matches. Runtime `jsonschema` validation is the alternative but adds a
  dependency to a tool that currently ships with one.
- **Score qualification:** compute a single `ScoreVerdict` view-model once in
  the pipeline and have all five renderers consume it. No renderer should
  decide independently how to caveat a number.
- **Agent guidance:** make `instructions.py` the source and generate `skills/`
  from it, or vice versa. Two hand-maintained copies of the same instructions
  will drift again.

  **Partly closed by enforcement, 2026-09-09.** Generation is still the right
  end state and is a larger change than it looks — these are different formats
  for different consumers and the prose in each is shaped for its audience. But
  the half that actually caused harm is now mechanical:
  `tests/unit/test_agent_guidance.py` extracts every flag from every line in
  the shipped guidance that invokes one of our console scripts, and fails if
  the CLI would reject it. Invocation lines rather than all prose, so the docs
  can still name another tool's flags — `--only-verified` is TruffleHog's. It
  also fails if `--changed-only` is mentioned without saying it is reserved and
  exits 2, which is the exact sentence that shipped wrong.
- **Packaging:** delete the `package-data` line, or restore the `data/`
  directory if the standards map moves back to data files (see §5).

## 4. Problem 3 — no integration tests and no real scanner fixtures

**Severity: high. Fix third — cheapest of the three. — CLOSED 2026-09-09, see D14.**

`tests/fixtures/` and `tests/integration/` **exist and are empty.**
`CONTRIBUTING.md` mandates per-scanner fixtures ("at least one HIGH true
positive, one false positive that should be suppressible, and one parse-failure
case") and cites `tests/integration/test_scoring_drift.py`, which does not
exist. All 151 tests live in `tests/unit/` and drive adapters with hand-written
mock subprocess output.

For a tool whose entire purpose is parsing eleven other tools' output formats,
every parser is currently verified against *the author's belief about the
format* rather than the format. Two concrete instances of this class already
occurred: the OSV-Scanner v1→v2 CLI change, and `pip-audit --locked` semantics,
both of which had to be checked against the real tools during review rather
than being caught by a test.

### Fix

Commit one real captured output per scanner under `tests/fixtures/<scanner>/`,
refreshed deliberately when a scanner is upgraded. Add the scoring-drift
regression test that `CONTRIBUTING.md` already promises. This converts a whole
class of "the upstream format changed" defect from a production surprise into a
test failure.

**Done, partially and explicitly so.** `tests/fixtures/scanner-output/` holds
genuine output from njsscan, RuboCop, gitleaks, gosec, pip-audit and semgrep,
captured against a deliberately-vulnerable tree with local paths rewritten and
nothing else edited. `tests/integration/test_scanner_output_fixtures.py` drives
each adapter against its real capture.

Six of fifteen scanners are covered, because only tools installable on the
capture host could produce real output — fabricating the rest would recreate
the exact defect this fixes. The remainder are named in
`SCANNERS_WITHOUT_A_REAL_CAPTURE` with the reason, and a test fails if that
list drifts out of step with the directory, so the gap stays visible rather
than becoming folklore.

`tests/integration/test_scoring_drift.py` now exists. It pins the letter bands,
the severity ordering, the worst-category rule, and the property that a perfect
score sits beside failed coverage without either deriving from the other. It
proves the scale is *stable*; D17 is what establishes it is *correct* — the
corpus now carries vulnerable-by-design anchors and the scale orders the two
populations perfectly (AUC 1.00). D5 is closed.

## 5. Problem 4 — the score's null state is "perfect" — CLOSED 2026-09-09

**Severity: medium. Design decision required before any code changes.**

With zero findings, every category grades 5.0, and
[`scoring.py:152`](../src/secure_code_audit/scoring.py#L152) takes
`overall = min(per_category.values())` → 5.0 → **A+**. A repository where seven
scanners failed to resolve still reports A+.

The score is structurally incapable of expressing "we did not look." That is
precisely why coverage had to be introduced as a parallel axis, and why five
renderers now carry qualification logic (§3). The current arrangement is
defensible, but it asks every reader to mentally combine two numbers.

Two smaller consequences of the same model:

- `worst_category` is `min()` over ties
  ([`scoring.py:150`](../src/secure_code_audit/scoring.py#L150)), so it reports
  the first category in enum order whenever grades are level. Reports currently
  say *"Worst category: `secrets`"* on repositories with zero secrets findings.
- Every category is normalized by *total* scanned LOC
  ([`scoring.py:96`](../src/secure_code_audit/scoring.py#L96)), and
  `paths.exclude_patterns` is simultaneously the scan scope and that
  denominator. Narrowing scan scope therefore moves the grade in a direction
  that is not obvious from the config.

### Closed

`security-pillar.json` reports `condition: null` whenever coverage is
incomplete, so the artifact `maintainability-agent` reads can never present an
unscanned repository as measured — a perfect practice level with no evidence
reports `unverified`, never `healthy`. That is MA's own rule
([ADR 007](https://github.com/marshallguillory86/maintainability-agent/blob/main/docs/adr-007-pillars-and-practice.md)
§2) applied at the seam between the two tools.

**And internally.** `ScoreReport.per_category` grades `None` where no scanner
in the run could read that category, `overall` is `None` when nothing was
measurable, and `letter` is `None` beside it. Never zero — a 0.0 would claim
knowledge of poor quality nobody has.

Measurability is computed in the orchestrator, not in `scoring`. Working it out
means knowing which scanners ran and what each reads, and a rubric that can
reach into the scanner layer is a rubric that can grow a special case for a
particular repository — MA keeps the same boundary. A scanner counts only if it
*covered* its ground, and a category with findings is measurable by definition
whatever the domain table says, because scanners report outside their declared
domain routinely.

**This closed the half of P3 that survived.** The P3 test used to assert that
removing a scanner *raises* the raw estimate — 0.00/F to 5.00/A+ — and then
that the grade was withheld anyway. The estimate no longer rises. It
disappears: the run that looked at nothing reports no number at all, and
`min_score` refuses it rather than passing by default.

### Open question



Should the deliverable be a single verdict rather than a score plus a coverage
status the reader must combine? Resolve this before touching the scoring code;
it is a product decision, not a refactor.

## 6. Smaller structural debt

- **`cli.py` is orchestrator, pipeline, and presenter** in 501 lines. Extracting
  `_prepare_audit`, `_run_scanners`, `_ingest_sarif_imports`, `_write_outputs`,
  and `_exit_code` brought `_do_audit`
  ([`cli.py:218`](../src/secure_code_audit/cli.py#L218)) under this project's
  own complexity standard, but there is still no `Audit` object. The pipeline is
  a straight-line function threading a dozen locals, and load-bearing ordering —
  classification must happen *before* suppression, or a suppressed
  `tool_unavailable` would read as a successful scan — is recorded only in a
  comment.
- **`standards.py` is 523 lines**, roughly 390 of them a hand-written
  `(scanner, rule_id) → StandardsEntry` dict beginning at
  [`standards.py:95`](../src/secure_code_audit/standards.py#L95). Adding a
  mapping requires a package release, operators cannot extend it (the module
  docstring says so), and Semgrep alone publishes thousands of rules. This wants
  to be shipped data with an operator overlay. The `(scanner, "*")` wildcard
  fallback is currently absorbing the coverage gap.
- **`--changed-only` is a flag that always exits 2.** Implement it or delete it;
  a permanently-erroring flag is API debt that has already caused documentation
  drift.
- **Two console scripts** (`secure-code-agent`, `secure-code-audit`) for one
  entry point.
- **`secure-code-report.json` is not gitignored** while `secure-code-report.md`
  is, so a CI-shaped local run leaves an untracked file behind.
- **`environment: name: pypi`** in `release.yml` requires that environment to
  exist in repository settings before the first tagged release will publish.

## 7. Recommended sequence

1. ~~**`ScanResult` for adapters** (§2).~~ **Done 2026-09-09** (D13). Highest
   defect-elimination per hour, and a prerequisite for §3.
2. ~~**Real scanner fixtures and the scoring-drift test** (§4).~~ **Done
   2026-09-09** (D14), for the six scanners installable on the capture host.
3. ~~**Single `ScoreVerdict` view-model** (§3, row 2).~~ **Done 2026-09-09.**
   `Verdict` existed but two renderers were never wired to it and kept a weaker
   condition, so the markdown report and PR comment claimed grades the JSON
   withheld. All outputs read the one verdict, and
   `tests/integration/test_verdict_consistency.py` asserts they agree.
4. ~~**Generate the config schema from the dataclasses** (§3, row 1).~~
   **Reconsidered and closed by enforcement, 2026-09-09.** The schema is nested
   where `Config` is flat, so generating either from the other needs a mapping
   layer that would itself be a third source of truth.
   `tests/unit/test_contract_sync.py` holds them in step instead.
5. ~~**Decide the score model** (§5).~~ **Closed 2026-09-11 by D16 and D17.**
   The model is a per-kLOC density, `secrets` excepted as a count, worst
   category drives the overall, and the grade is explicitly second class to
   the work order. Every number in it is now chosen from a measurement.
6. ~~**Calibrate the condition scale** (D5).~~ **Closed 2026-09-11 by D16 and
   D17.** Method delivered 2026-09-09, narrowed 2026-09-10, and finished when
   the corpus grew a bad end. The nineteen-repository pinned corpus carries
   both populations — fourteen maintained projects and five written to be
   vulnerable — and re-derives exactly
   ([`calibration/`](../calibration/README.md), [`calibration.md`](calibration.md)).
   The scale orders them perfectly: AUC 1.00, separation +1.26, maintained
   median 3.41 (B), every vulnerable-by-design application at F.
   `test_scoring_drift.py` now pins actual values as well as properties.
   Three bands (A−, B, C) hold no observation and D17 records that they are
   presentational granularity rather than measured thresholds.
7. Resume feature work and defect fixing.

Steps 1–4 are done as of 2026-09-09. Most defects traded during recent review
cycles were downstream symptoms of §2 and §3, and closing them did end that
pattern — the defects found since came from a different place entirely: the
repository running its own gate in CI at the floor it declares, which surfaced
four that no amount of reading the code would have.

Steps 5 and 6 are the two open **decisions**, not defects. Both are about
whether the number this tool reports means anything, and neither can be settled
by a refactor.
