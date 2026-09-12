# Decision register

> Status: **v0.10.0 — 2026-09-11.** The decision register. D1–D19.

Product decisions that constrain the code, with the reasoning and the rejected
alternatives. Modelled on `maintainability-agent`'s register, which exists
because *a decision that lists only the chosen path is a rationalization*.

A decision belongs here when it settles a question the code alone cannot
answer. Defects belong in [`release-blockers.md`](release-blockers.md);
architecture belongs in [`architecture.md`](architecture.md); intent belongs in
[`product-intent.md`](product-intent.md).

| # | Decision | Date | State |
| --- | --- | --- | --- |
| D1 | The line is at executing what the tree supplies, not at distrusting repositories | 2026-09-08 | Accepted |
| D2 | Unknown configuration keys are rejected, not ignored | 2026-09-08 | Accepted |
| D3 | The MA Security pillar is fed by an artifact, not by MA executing this tool | 2026-09-08 | Accepted — [built](ma-integration.md) |
| D4 | A failing security audit fails MA's CI | 2026-09-08 | Accepted |
| D5 | The condition scale must be calibrated against a corpus before it is trusted | 2026-09-08 | **Closed** by D16 and D17 |
| D6 | Scanner licences are judged by mechanism, not by name | 2026-09-08 | Accepted |
| D7 | The project declares a minimum tool floor, and defaults to it | 2026-09-08 | Accepted |
| D8 | Floor tools have a cadence; repository-level ones arrive by import | 2026-09-08 | Accepted |
| D9 | Our ruleset is the offline floor, bounded to language primitives | 2026-09-09 | Accepted |
| D10 | Rules ship as a versioned, digest-identified profile | 2026-09-09 | Accepted |
| D11 | Author a rule only where no floor scanner already covers it | 2026-09-09 | Accepted |
| D12 | The coverage check, run for the other four languages | 2026-09-09 | Accepted |
| D13 | Adapters state their outcome; nothing infers it from a finding's name | 2026-09-09 | Accepted |
| D14 | Parsers are tested against real captured output, and the gap is declared | 2026-09-09 | Accepted |
| D15 | A scanner's severity is not a measure of consequence, and nothing may rank on it | 2026-09-11 | Accepted |
| D16 | The grade is a density, and the gate is what catches a vulnerability | 2026-09-11 | Accepted — amended by D17 |
| D17 | Calibrated against both populations; `secrets` is a count, and three bands are unmeasurable | 2026-09-11 | Accepted — closes D5 |
| D18 | Our output is never our input; a variable reference is not a credential | 2026-09-11 | Accepted |
| D19 | `scoring_model`: the instrument says when it changed, and a digest holds it honest | 2026-09-11 | Accepted — schema v2 |

---

## D1 — The line is at executing what the tree supplies

**Question.** Are audited repositories trusted? `threat-model.md` called
repository content untrusted *and* called the operator the author of the
config, while `secure-code-agent.json` normally lives in the audited tree. Both
could not be true, and the code took the permissive reading — a relative
`scanners.<name>.command` resolved under the audit target and was executed.

This is the same question `maintainability-agent` faced in its security queue,
where eslint executed the tree's own configuration while `SECURITY.md` said the
agent does not execute scanned code.

**Options.**

1. *Repositories are trusted.* Correct the docs to say so. Cheap and honest, but
   narrows who can safely run the tool — and this tool's whole purpose is
   auditing code you have reason to doubt.
2. *Repositories are untrusted.* Refuse all repository-supplied configuration.
   Costs the documented tree-local interpreter workflow, which is a real
   product change for a legitimate use.

**Decision — neither framing; the line moved.** MA drew its line at *executing
code* rather than at trusting repositories, and the same line is correct here.
Configuration is an instruction to execute, so:

- A config **outside** the tree is an operator artifact and may name a
  tree-local interpreter — the documented workflow survives.
- A config **inside** the tree is repository content, and a command it names
  that also resolves inside the tree is refused. The scanner reports
  `unavailable`, which fails required coverage rather than skipping quietly.
- `--trust-target-config` is the operator's explicit opt-in, and is
  **command-line only**: a config file cannot grant itself the trust the flag
  exists to withhold.

**Consequence.** The containment check runs on the resolved path from every
resolution route, not just the relative-path branch, because `PATH` can contain
`.` or a tree-local directory.

## D2 — Unknown configuration keys are rejected, not ignored

**Question.** `secure-code-agent.schema.json` declares
`additionalProperties: false`, but the runtime loader ignored unknown keys. The
schema is not enforced at runtime ([`architecture.md`](architecture.md) §3), so
the two disagreed.

**Decision.** The loader rejects unknown top-level keys. A key this tool does
not read cannot change what it does, so a config that names one is either a
typo that silently disabled a gate, or an assertion of a privilege that was
never granted. Both deserve an error rather than silence. Keys withdrawn on
purpose — `asvs_level` — keep their specific reason instead of the generic
message.

**Consequence.** Two sources of truth remain. Generation was the intended
fix and was rejected on inspection: the schema is nested where `Config` is
flat — `paths.include_extensions` and `paths.exclude_patterns` are one JSON
object and two dataclass fields, and `gates`/`outputs` are free-form dicts with
no dataclass at all — so generating either from the other means a mapping layer
that would itself be a third source of truth. They are held in step by
`tests/unit/test_contract_sync.py` instead, which asserts the loader and the
schema accept the same keys at both the top level and the per-scanner level,
and that no `Config` field is settable only by editing source. Enforcement
rather than generation, and the reason recorded rather than the intent
restated.

## D3 — The MA Security pillar is fed by an artifact

**Question.** `maintainability-agent` declares Security as a `DELEGATED` pillar
naming this tool ([MA ADR 007](https://github.com/marshallguillory86/maintainability-agent/blob/main/docs/adr-007-pillars-and-practice.md)
§1), but has no ingestion path. Should MA execute `secure-code-agent`, or
ingest an artifact it produces?

**Decision.** This tool writes `security-pillar.json`; MA ingests it via
`--security-pillar <path>`.

**Built 2026-09-09.** `--security-pillar <path>` emits it; the contract is
[`ma-integration.md`](ma-integration.md). The document carries MA's own two
axes — practice level from configuration and CI, code condition from the
scanners — and never their mean. Everything structural is reused rather than
re-derived: the scope vocabulary, the posture matrix and its thresholds come
from MA's `_pillars.py`, and the maturity rubric with its `MAX_WITHOUT_CI` cap
from `_practice.py`. Two tools reporting "level 3" or "healthy" about the same
repository must mean the same thing by it.

Copied by value, not imported. A dependency edge between the two packages would
make them releasable only together, which is the property MA's ADR 008 protects
when it refuses a combined MCP server. `test_posture_matches_mas_matrix` is
what keeps the copies honest.

**`condition` is null whenever coverage is incomplete**, and this is the half
that matters most. Our score is a rate over findings, so removing scanners
removes findings and the number rises — measured once at 0.00/F to 5.00/A+.
Handing that to MA would launder an unscanned repository into a pillar report
that looks measured. A perfect practice level with no evidence reports
`unverified`, never `healthy`.

**Why not have MA execute this tool.** MA's P1 keeps analysis free of network
access and tool acquisition opt-in. Shelling out would put a network-capable
scanner orchestrator inside MA's deterministic core and import this tool's
trust boundary — including D1 — into MA's. Artifact ingestion matches MA's
existing adapter rule: *ingest tool output, preserve provenance.*

## D4 — A failing security audit fails MA's CI

**Decision.** When the Security pillar reports a failure, MA's CI fails.

**This diverges from MA precedent, deliberately.** [MA ADR 002](https://github.com/marshallguillory86/maintainability-agent/blob/main/docs/adr-002-null-verified-grade-in-ci.md)
rejected coupling `verified_grade` to `--fail-on-gate` on the grounds that it
would turn a hard-finding gate into an evidence-completeness gate — *"a new CLI
contract, not a consequence."* That reasoning still holds; the contract is
being changed on purpose rather than by accident, and it is recorded here so
the divergence is visible to whoever implements it.

**Open sub-question.** Whether *insufficient evidence* fails CI, or only
*findings*, is not settled by this decision. D5 bears on it: gating on a scale
nobody has calibrated would fail builds on an arbitrary threshold.

## D5 — The condition scale must be calibrated

**Question.** `_LETTER_GRADE_TABLE` carries the comment *"mirrors
maintainability-agent"*. It borrowed MA's **bands** without MA's **calibration
study**, and the `sqrt(LOC/1000)` dampener is an invented normalizer with no
corpus behind it. Nobody has established that A+ means anything.

MA learned this the expensive way at 0.5.0: absolute finding counts graded
repository *size*, scoring Django, pytest, black, tornado, httpx, lodash,
svelte and fastapi all at 0.0/F while a 53-file toy scored 4.6/A. The fix was
rates, normalized per dimension, calibrated so the corpus median earns a B.

**State: CLOSED — 2026-09-11, by D16 (the normalizer) and D17 (the corpus,
the `secrets` exception, and what the bands can and cannot mean).** The
history below is kept because the route matters: each narrowing was wrong in a
way the next measurement caught, and the register is the record of that.

**State (historical): open, and narrowed to one question.** See
[`calibration.md`](calibration.md) for the study and
[`calibration/`](../calibration/README.md) for the harness and pinned corpus.

**What the study found, in the end: most of the floor was our own bug.** The
corpus median moved **0.00 (F) → 4.37 (A−)**, and every round of that except
the last was a defect in this tool rather than a property of the code it read.

The largest single one: **gitleaks reports repository-relative paths and every
other scanner reports absolute ones**, and every consumer that asked "where is
this?" resolved a relative path against the process working directory. So
`exclude_patterns` silently did not apply to gitleaks findings at all, and
every gitleaks finding scored as primary-tree wherever it lived — four
`tests/certs/*.key` files held `requests` at F, six documentation examples held
`flask` at F. Separately, `**/` did not match at depth zero, so `**/*_test.go`
never matched a root-level `context_test.go` and three of Gin's four
"production" secrets were test fixtures. Gin: **F → A+**.

**The inputs are now all answered.** The primary tree is scored; the test tree
and documentation are reported beside it and gated where the operator names
the category; dependencies are their own axis, gated but not graded as code
condition. Secrets are no longer force-scored onto the primary axis — nothing
static separates a live credential from a test certificate, so they are gated
from any axis rather than graded from all of them.

**An earlier revision of this entry claimed the residue was all true
positives and that the remaining question was what a grade should mean. That
was wrong.** Checking that a construct is present is not checking that a
defect is present. Django's "hardcoded passwords" are `EMAIL_HOST_PASSWORD =
""` and `SECRET_KEY = ""` — empty defaults. Its "SQL injection" hits include
an `ImproperlyConfigured` error message and a parameterised `cursor.execute`.
Its 56 `mark_safe` hits are the admin rendering its own escaped output.

A tool that grades Django, FastAPI, httpx and Flask all F is measuring how
talkative Bandit is on large Python codebases. That is the failure this
decision exists to prevent, and it was a defect to fix rather than a
judgement call to escalate.

**Fixed: repeats of one rule saturate.** Sorted worst-first, a rule's k-th
hit counts `weight / sqrt(k)`. Repositories at F went from four to two, httpx
F to B-, fastapi F to C, requests B- to B+, and none scored lower. The first
formulation broke P3 — `mean(weight) * sqrt(n)` let nine extra LOW findings
*improve* a grade — and is pinned against by a monotonicity test.

**Open at the time, and now concrete** — closed by D16. Django and Flask remained at F because of
`sqrt(LOC/1000)`, under which the largest repository in the corpus ranks
worst: django 15.53 normalized against flask 9.12, inverting to 1.29 and 3.17
per-kLOC. That is size bias in the normalizer meant to remove it.

**Corpus coverage was the blocker, and fixing it largely answered the
question.** Six of fourteen repositories were scoring near-perfectly because
they were *unexamined* rather than clean. Two causes, and only one was
structural:

*Environment.* `njsscan` and `rubocop` were simply not installed, so
JavaScript and Ruby had no scanner that reads them. Python repositories were
producing 712 to 5,107 real findings each against nought to four for
everything else — three orders of magnitude, none of it about those projects
being cleaner. Installing both moved `axios` 5.00 → 4.38, `lodash`
4.59 → 4.48 and `sinatra` 3.10 → 2.79.

*Structural, and already decided.* D12 records why Go and Java cannot be
read at all: gosec analyses Go by invoking the target's own build tooling,
PMD covers none of the patterns, SpotBugs needs compiled bytecode. Four
repositories stay unreadable.

Those four were still in the median and holding it up — **their own median is
5.00**, four perfect scores for repositories nobody looked at. The study now
applies the product's own rule to itself (P7: score only where enough was
examined) and reports the distribution over the examined set, naming what it
left out.

| set | n | median |
| --- | ---: | --- |
| examined | 10 | **3.38** |
| unexamined | 4 | 5.00 |
| all fourteen | 14 | 4.37 |

**3.38 is in the B band, which is the target.** `maintainability-agent`
calibrates so a mature-OSS corpus medians at a B, this corpus does so
already, and the spread across the examined ten runs 0.00, 0.44, 2.47, 2.58,
2.79, 3.98, 4.38, 4.48, 4.61, 5.00 — a distribution rather than the cliff it
was this morning. No band edge needs moving to achieve that.

**What remains is one repository, not the scale.** Django still reads 0.00
under `sqrt(LOC/1000)`, which ranks the largest repository in the corpus
worst — 15.53 normalized against Flask's 9.12, inverting to 1.29 and 3.17
per-kLOC. That is size bias in the normalizer meant to remove it, and it is
now a single identified defect rather than an uncalibrated scale. It is still
not changed here, because switching to per-kLOC weakens the gate: a synthetic
1,939-line repository carrying SQL injection, command injection,
`pickle.loads`, `yaml.load`, `eval`, MD5 and hardcoded credentials scores
0.00 F today and would land near D.

**Open at the time — band edges** — closed by D17, which found the blocker
was that this corpus had no bad end to place D and F against. The centre was
already defensible: 4.37 (A−) against
MA's 4.0 target. The *distribution* is not — nine repositories at 4.15 or
better, four at 0.15 or worse, almost nothing between. That cliff comes from
clamping a linear slope at zero, not from the inputs.

Two adjustments were measured and neither is adopted. **√n per rule** — one
rule firing 81 times as one strongly-evidenced fact rather than 81 defects —
is the only lever that moves the floored repositories (median 4.56, one at F).
It must not be adopted to hit a target, because the target is already met and
√n overshoots it; the argument has to be that repeated identical findings are
correlated evidence, which is a claim about what a rule count means.

**An earlier version of this study was wrong and is corrected in place.** It
filtered test findings out of the numerator while still dividing by the whole
tree's LOC, and reported a median of 3.10 — a B — that the corrected
measurement does not support. That is the same numerator/denominator mismatch
`exclude_patterns` caused once already, reproduced in the tool built to
measure it. Doing the split inside the product is what makes it unavailable.

Until band edges are chosen the scale is uncalibrated, and anything consuming
it (D3, D4) should treat it as such.

## D6 — Scanner licences are judged by mechanism, not by name

**Question.** `CONTRIBUTING.md` required every scanner to be
*"MIT/Apache-2.0/BSD licensed (no GPL — license-surface contamination)"*. Two
shipped tools violated it — TruffleHog is AGPL-3.0, Hadolint is GPL-3.0 — and
neither caused a problem. A rule that is stated, violated, and harmless is
worse than no rule: it teaches people that the rules are decorative.

**Was the rule right?** No, for this architecture. Copyleft reaches a combined
work through linking, vendoring or bundling. This tool does none of those — it
runs `subprocess.run(args=[...], shell=False)` and reads JSON back. Separate
processes exchanging arguments and output are separate programs. The
"never install anything" principle compounds it: the operator installs the
scanner, so there is no distribution by us at all, and most copyleft
obligations attach at distribution.

**Decision.** Three criteria keyed to mechanism:

1. Any OSI-approved licence is acceptable for a tool invoked as a subprocess
   and never distributed. Linking, vendoring or bundling still requires a
   permissive licence.
2. AGPL tools are optional and off by default — so we do not silently hand a
   hosted-service source-offer obligation to an adopter, and so adopters whose
   policy excludes AGPL are not blocked.
3. Rule content and data are licensed separately from engines and checked
   separately.

**Criterion 3 exists because of a live case the old rule missed entirely.**
Semgrep's engine is LGPL-2.1, but Semgrep-maintained registry rules moved to
the Semgrep Rules Licence in December 2024 — internal, non-competing, non-SaaS
use only. `--config=auto` fetches those. A security tool that is arguably a
competing product, and that someone may run as a service, was pulling rules
under a licence restricting exactly those two uses. A licence rule about
engines could never have caught it. The offline ruleset this project ships is
its own work and is unaffected.

**Consequence.** TruffleHog and Hadolint become documented opt-in choices
rather than silent violations. This is engineering reasoning about how the
licences apply to this architecture, not legal advice; the Semgrep rules
licence in particular is worth confirming with counsel before it is relied on
commercially.

## D7 — The project declares a minimum tool floor, and defaults to it

**Question.** Every registered scanner defaulted to enabled, `require_scanners`
was per-repository config with no floor, and this repository's own audit ran
three of twelve tools. A tool whose purpose is determining whether code is
secure was checking itself with Bandit, pip-audit and a regex pack — and
nothing in the product said that was too few.

**Decision.** `scanners/floor.py` declares the minimum set, the tools
deliberately left out, and the reason for each. Two rules keep it honest:

- **A floor tool that does not apply is not a gap.** Applicability is declared
  per tool and evaluated against what the tree actually contains, so a
  single-language repository is not permanently incomplete. An alarm that is
  always on is not an alarm.
- **Overlap must earn its place.** Four tools reporting one CVE is not four
  times the assurance; it is one finding counted four times in a score that
  normalizes over findings.

The floor: `builtin_rules`, `bandit`, `semgrep`, `pip_audit`, `osv_scanner`,
`gitleaks`, `checkov`, `trivy`, `scorecard`. Opt-in: `trufflehog` (duplicates
gitleaks for detection; AGPL; verification is the genuine gain), `hadolint`
(overlaps checkov and trivy; GPL), `npm_audit` (osv_scanner covers the same
advisories with fewer false positives and without needing Node).

> Membership has changed since: [D12](#d12--the-coverage-check-run-for-the-other-four-languages)
> adds `njsscan` and `rubocop` to the floor and `gosec` to the opt-in set.
> `scanners/floor.py` is the authority; this paragraph is the reasoning at the
> time the floor was declared.

`gates.require_scanners: ["floor"]` requires the declared set without
enumerating it, so the membership stays maintained here rather than copied
into every repository's config and left to rot.

**First run found two defects the old three-scanner setup could not expose.**
Scorecard timed out at the 600s default because it makes dozens of GitHub API
calls, and its version probe printed `Error: unknown flag: --version` into the
version column of a report that otherwise claimed it ran fine. Adapters now
declare their own timeout default, and a nonzero version probe reports no
version rather than an error string. That is the floor doing its job on day
one: more tools running is more of the tool under test.

## D8 — Floor tools have a cadence, and repository-level ones arrive by import

**Question.** The floor's first CI run failed on Scorecard, twice. It timed out
at 600s, and again at 1800s: against this repository it takes over half an
hour, because it makes dozens of GitHub API calls. Raising the timeout again
would have made every pull request wait thirty minutes.

**The timeout was never the problem.** Scorecard answers questions about the
*repository* — branch protection, release signing, token scopes, dependency
pinning. Those answers do not move between commits. Asking them on every change
is asking the wrong question at the wrong rate, and no timeout value fixes a
cadence mismatch.

**Decision.** `ToolPolicy` gains a cadence. `commit` tools answer questions
about the code in front of them and run in the per-change gate. `repository`
tools run on their own schedule and reach the audit as an imported SARIF —
which is D3's rule applied to ourselves rather than only to consumers.

Scorecard is the first repository-cadence tool. It stays **in the floor** —
demoting it to optional would concede the supply-chain domain by default, which
is what the floor exists to prevent. `.github/workflows/supply-chain.yml` runs
it weekly and on pushes to `main`, publishes SARIF to code scanning, and
retains the artifact for `--sarif-import scorecard=…`.

**Deferred is not silent.** A floor tool a run does not evaluate is named in
preflight and in the report — `· scorecard deferred repository cadence` —
because an omission the reader cannot see is indistinguishable from a pass, and
that is the failure this project exists to remove.

**Consequence.** Imported Scorecard coverage is `unverified` per D3: an
artifact we did not watch being produced. That is the correct label, and it is
visible in every output.

## D9 — Our ruleset is the offline floor, bounded to language primitives

**Question.** `product-intent.md` §5 principle 2 said *"no parallel ruleset
competing with Semgrep or Bandit."* We ship two rulesets — the built-in regex
pack and the offline Semgrep profile — so the principle was already violated
the day it was written. Meanwhile `--config=auto` fetches registry rules under
the Semgrep Rules Licence, which permits internal, non-competing, non-SaaS use
only, and this project is arguably a competing security product.

**Marshall's ruling (2026-09-09):** *"Our ruleset is the offline floor, not a
competitor. Its job is: when there is no network and no registry, you still get
the highest-consequence patterns."* Online, the maintained registries do the
job, because online is where they are available.

**Why an escape hatch was not available.** OpenGrep is a healthy LGPL-2.1 fork
of the Semgrep engine, but `opengrep/opengrep-rules` — the permissively
licensed rules fork — has six stars and was last touched in November 2025.
There is no maintained, permissively licensed community ruleset to adopt, so
authoring is the only path that resolves the licence question.

**The bound, and why it is enforceable.** Maintenance cost is driven by rule
*shape*, not rule count:

- **Language primitives** — `shell=True`, `eval`, `pickle.loads`,
  `hashlib.md5`, `verify=False` — are constructs the language itself provides.
  They have not changed in a decade and will not. Sixty of them is an asset.
- **Framework APIs** — Django ORM internals, Express middleware, Spring
  annotations — rot with every framework release. That is where a funded rules
  team earns its keep and where a one-maintainer project bleeds.

So the offline profile takes primitives and **refuses framework rules**, and
`test_the_offline_profile_refuses_framework_rules` fails the build on a rule
that names one. A bound enforced only in review is not a bound.

**What makes a small set worth having.** Not count. Every rule carries a CWE,
an OWASP bucket, a confidence and a version, and every rule has a positive
fixture it must flag *and* a negative fixture it must not. Registry rules
deliver CWEs inconsistently — before this work every Semgrep finding arrived
with no CWE at all — and a fully mapped 26-rule set is worth more to a
standards-anchored tool than a partially mapped 3,000-rule one.

**Parity remains a non-goal.** A stale ruleset claiming to be a standard is
worse than a small one honestly labelled, and `docs/scanners.md` labels it.

## D10 — Rules ship as a versioned, digest-identified profile

**Question.** "Semgrep found three things" is not a claim anyone can check. A
result is only reproducible if you can say which rules produced it, and re-run
against the same baseline later.

**Decision.** The offline rules are a **profile** with an id, a version and a
digest, cited in scanner provenance as `sca-offline@1.0.0 (cff6cb1e5519)`.

This is the STIG benchmark model: a named baseline, a release number, and rules
that each carry their own version, so a finding can be cited and re-checked.

**The digest is the part that is evidence.** A version is an assertion by
whoever edited the file. A digest is computed from the bytes that actually ran.
Someone editing the ruleset inside an installed wheel leaves the version saying
1.0.0; the digest notices, and a test asserts it does.

**Bump the version when rules are added, removed, or change meaning.** A rule
whose pattern is broadened has changed meaning even with an unchanged id, and a
report citing an unchanged version after that claims a comparison it cannot
support.

## D11 — Author a rule only where no floor scanner already covers it

**Question.** `CONTRIBUTING.md` has forbidden "shipping a parallel ruleset to
Semgrep / Bandit / CodeQL" since the first commit. Marshall asked whether that
principle still made sense, since nobody remembered writing it.

**It made more sense than we credited, and it had just been violated.** The
principle's target was never rule-writing as such — it sits in a scope-creep
list beside "writing a new AST analyzer", "SaaS dashboard" and "telemetry". Its
target is **duplicating detection a scanner already does**, because then you
have built a worse version of that scanner and now maintain it.

**Measured, not argued.** Running Bandit against the profile's own fixture:

| | |
| --- | --- |
| Python rules in the profile | 19 |
| Fully or partly covered by Bandit | **17** |
| Genuinely unique | 2 |

Bandit found 23 distinct test types where the profile had 19 rules, including
`B113 request_without_timeout`, which the profile did not cover at all.

**Why the reasoning failed.** The rules were justified as "the offline floor".
That argument does not survive the observation that **Bandit is itself
offline** — Apache-2.0, no network, no registry. The offline/online framing was
imported from the Semgrep Rules Licence problem, which is real, and applied to
a language where a different tool had already solved it.

**Decision.** Author a rule only where no floor scanner already covers it. In
practice that means the profile covers what Bandit cannot read: JavaScript,
TypeScript, Go, Ruby and Java have no offline SAST in the floor at all. Python
is admitted only for gaps Bandit measurably leaves, and each such rule must
declare the gap in a `covers-gap` metadata field.

> **The second sentence was wrong, and D12 is the correction.** "JavaScript,
> TypeScript, Go, Ruby and Java have no offline SAST in the floor at all" was
> asserted without running any of those tools. njsscan and RuboCop both exist,
> both install offline, and both cover rules this decision let stand. The
> principle here survives intact; only the claim about which languages were
> uncovered was false. See
> [D12](#d12--the-coverage-check-run-for-the-other-four-languages).

**Enforced, not remembered.** `test_no_python_rule_duplicates_bandit` runs both
tools over the fixtures and fails on any Python rule flagging a line Bandit
already flags. `test_the_profile_covers_languages_the_floor_cannot_read_offline`
asserts the languages that justify the profile existing. A bound enforced only
in review is not a bound — the same conclusion D9 reached, applied to the
mistake D9 did not prevent.

**Consequence.** The profile went from 26 rules to 23, and became more valuable:
2 Python, 7 JavaScript/TypeScript, 5 Go, 4 Ruby, 5 Java. Smaller, no overlap,
and every rule covering something nothing else in the floor can see.

**A precision defect fell out of the same pass.** The Java command-execution
rule flagged `new ProcessBuilder(new String[]{...})` — the *recommended fix* —
as the defect. A rule that reports the remediation as the problem trains people
to ignore the rule. It is now narrowed to `Runtime.exec`.

## D12 — The coverage check, run for the other four languages

**Status.** Accepted, 2026-09-09.

D11 shrank the Python rules because Bandit already covered seventeen of
nineteen. It then justified the remaining twenty-one rules with a sentence that
was never tested: *"JavaScript, TypeScript, Go, Ruby and Java have no offline
SAST in the floor at all."* That is an assertion about tools that exist, made
without running any of them. The standing rule is that a built-in detector
requires a **proven** gap, and that the evidence is produced before the code,
not after. It was not. This is that check, run late.

**Method.** For each language, install the candidate FOSS tools and run them
against the same positive and negative fixtures the profile's own suite uses.
A rule is a duplicate when the tool flags the same line for the same primitive
with no framework context required. A tool that needs a framework shape, a
build, or a toolchain we do not provision does not count as coverage.

**Result.**

| Language | Tool | Licence | Ran | Covers | Leaves |
| --- | --- | --- | --- | --- | --- |
| JavaScript | njsscan 1.0.0 | LGPL-3.0-or-later | yes | `md5`, `Math.random`, `NODE_TLS_REJECT_UNAUTHORIZED` | `child_process.exec`, `eval`, `new Function`, `innerHTML` |
| Ruby | RuboCop 1.28.2 `--only Security` | MIT | yes | `eval`, `Marshal.load`, `YAML.load` | `system()` interpolation, `Digest::MD5` |
| Ruby | Brakeman | MIT | no | — | Rails-only; does not analyze plain Ruby |
| Go | gosec 2.29.0 | Apache-2.0 | **no** | — | requires the Go toolchain on the host |
| Java | PMD 7.7.0 | BSD-2-Clause | jar read | **none of the five** | all five |
| Java | SpotBugs / find-sec-bugs | LGPL-2.1 | no | — | requires compiled bytecode |

**Two tools cover ground we had written rules for, and both are clean.**
njsscan and RuboCop each produced zero findings on the negative fixtures, so
wiring them costs no precision. Under the standing rule the tool wins, so both
are wired and the rules give way to them: three are deleted outright
(`javascript.weak-hash`, `javascript.weak-random`,
`ruby.unsafe-deserialization`) and two are narrowed to the half the tool leaves
— `ruby.code-injection` drops plain `eval` and keeps `instance_eval` /
`class_eval`, and `javascript.tls-verification-disabled` drops the env-var form
and keeps the per-request `{rejectUnauthorized: false}`.

**Three boundaries are real, and each has a mechanism behind it.**

*njsscan's silence is structural, not incidental.* It has rules for `eval`,
`child_process.exec` and DOM XSS — they did not fire because they are taint
rules gated on an Express handler shape, `function ($REQ, $RES, ...)` with a
`$REQ.$QUERY` source. In a CLI script, a library, a build step or a Lambda
handler there is no such shape and the rules are quiet. Its TLS rule matches
only `process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'`; the far more common
per-request `{rejectUnauthorized: false}` is not covered, so that rule of ours
stays.

*gosec cannot read Go source on its own.* It loads packages through
`go list` and fails outright without the toolchain — `go command required, not
found`. The distinction that matters is **running the tool versus reading the
target**: every floor tool needs some runtime to execute itself, and that is
unremarkable. gosec is different in that analyzing a target means invoking
*that target's* build tooling. This is precisely the boundary MA's ADR-012
draws for SpotBugs, where needing a build makes a tool unavailable rather than
silently empty. So gosec is wired as an optional tool that declares why it may
not run, and njsscan and RuboCop — which parse source directly and need only
themselves — are in the floor.

*Java has no source-level FOSS SAST worth wiring.* PMD parses source and needs
no bytecode, but its entire Java security category is two rules,
`HardCodedCryptoKey` and `InsecureCryptoIv`, and neither touches
`Runtime.exec`, `readObject`, MD5, ECB or `java.util.Random`. Searching every
PMD Java category for those primitives returns only false leads — a rule about
`gc()`, one about `exit()`, one about JDBC result sets. Java is a proven gap.

**Consequence.** The profile drops from 23 rules to 20 and the floor gains two
tools that are better at their own languages than we would be: 5 Java, 5 Go,
5 JavaScript, 3 Ruby, 2 Python. The gap that remains is now measured rather
than assumed, and every rule in a language a floor tool can read has to name
the gap it covers in a `covers-gap` metadata field or fail the build.

**The lesson is the one D11 already recorded and did not generalize.** D11
caught the Python error and then repeated it in the same paragraph for four
other languages. Running the check on one language and asserting the result for
the rest is not evidence. The check is now automated per language in
`tests/unit/test_offline_ruleset.py`, so the next rule added to a language a
tool covers fails the build instead of surviving to a later audit.

## D13 — Adapters state their outcome; nothing infers it from a name

**Status.** Accepted, 2026-09-09. Closes [`architecture.md`](architecture.md) §2.

**Question.** An adapter used to signal what happened to it by *naming a
finding*: `bandit.tool_error` meant FAILED, `bandit.tool_timeout` meant
TIMED_OUT, and anything starting `pip_audit.no_` meant NOT_APPLICABLE.
`classify_execution` then reverse-engineered the intent by prefix matching, and
counted real findings by *exclusion* — everything not starting `<name>.tool_`.

**Why that was worth changing before adding features.** Nothing enforced the
protocol: no type, no test, no lint. The convention was documented only by
example, and fifteen adapters had been written at four different times. An
adapter naming a control finding wrongly produced a *security* finding
silently; a real finding whose id began with the scanner's name plus `no_`
became a false NOT_APPLICABLE, which a required-scanner gate escalated into a
hard build failure. The architecture audit ranked this first on
defect-elimination per hour, and most defects traded during recent review
cycles were downstream symptoms of it.

**Decision.** `Scanner.scan()` returns a `ScanResult` — outcome, findings,
reason, scope. Outcome constructors (`completed`, `failed`, `timed_out`,
`unavailable`, `not_applicable`) live on the base class and *derive* the
control finding from the outcome, so the two cannot disagree. A non-COMPLETED
result without a reason raises: a failed scanner with no reason reaches a
report as a blank cell, indistinguishable from one nobody asked about.

**`classify_execution` is deleted, not deprecated.** It still worked, and that
was the problem — a functioning string-parser left in the tree is an invitation
to wire the next adapter into it. `execution_from_result` replaces it and does
no decoding at all.

**Scope moved onto the adapter.** `cli.py` carried `if name != "pip_audit":
return None` because there was nowhere on an adapter to declare what it
covered. `Scanner.scope()` is that place; `pip_audit` reports its mode and
inputs, `semgrep` cites the offline rule profile by digest, everything else
returns None.

**Two live defects surfaced during the migration**, both of the predicted kind.
`trufflehog` and `npm_audit` could return real findings *alongside* a control
finding — twenty parsed secrets and three unreadable lines — and the old
classifier's early return recorded `finding_count=0` while those findings still
reached the report. The count and the report disagreed because neither was the
source of truth. `failed()` now takes the partial findings explicitly: they are
reported, and the outcome stays FAILED, because a partial audit is not an
audit. Separately, `pip_audit._parse` returned a control finding from a parsing
helper, making a leaf function the thing that decided the run's outcome; it
raises now, and the caller states the outcome.

**A regression I introduced and caught.** Folding per-input timeouts into the
same failure list cost `npm_audit` and `pip_audit` their TIMED_OUT outcome.
Both fail coverage, so no gate changed — but only one of them tells an operator
to raise the timeout. Timeouts are tracked separately again.

**Enforced, not remembered.** `tests/unit/test_scan_protocol.py` asserts every
registered scanner returns `ScanResult`, that a non-COMPLETED result carries a
reason, that a failed run keeps its findings and loses its count, and — by AST
walk over every adapter — that none of them hand-builds a control finding. The
last one was verified against a synthetic offender rather than assumed to work.

## D14 — Parsers are tested against real captured output, and the gap is declared

**Status.** Accepted, 2026-09-09. Closes [`architecture.md`](architecture.md) §4.

**Question.** This tool's entire job is parsing fifteen other tools' output
formats, and every parser was verified against hand-written mock output — which
means against *the author's belief about the format*, not the format. Two
instances of that class had already bitten: the OSV-Scanner v1→v2 CLI change
and `pip-audit --locked` semantics, both caught by hand during review.
`tests/integration/` was empty, and `CONTRIBUTING.md` had cited a
`test_scoring_drift.py` that never existed.

**Decision.** Commit genuine captured output per scanner under
`tests/fixtures/scanner-output/`, and drive each adapter against it. Captures
are produced by running the real tool against a small deliberately-vulnerable
tree; local paths are rewritten to `/repo` and `/home/user` and nothing else is
edited. On a scanner upgrade, recapture — a fixture hand-edited to make a test
pass is precisely the belief this stops trusting.

**Six of fifteen, and the other nine are named.** Only tools installable on the
capture host could produce real output: njsscan, RuboCop, gitleaks, gosec,
pip-audit and semgrep. Writing plausible-looking output for the rest would
recreate the defect being fixed, so the remainder sit in
`SCANNERS_WITHOUT_A_REAL_CAPTURE` with a reason each, and a test fails if that
list drifts out of step with the fixtures directory. A parser with no real
capture is a known risk; an undocumented one is the same silence this project
rejects everywhere else.

**The gosec capture is the valuable one.** It is that tool's genuine output on
a host with no Go toolchain: exit 1, well-formed JSON, `"Issues": []`,
`"Stats": {"files": 0}`, and the failure recorded only under `Golang errors`.
The test asserts the capture still demonstrates that shape before asserting the
adapter handles it — so if a future gosec stops behaving this way, the fixture
says so rather than the test quietly passing for a new reason.

**Scoring drift is pinned, not calibrated.** The model is a chain of judgement
calls — severity weights, the `sqrt(LOC/1000)` dampener, the grade table, the
letter bands — and changing any of them silently re-grades every repository
ever scanned, including accepted baselines. The new tests pin the output of
that chain, plus the properties that must survive any retuning: severity
ordering is monotonic, informational findings never move the grade, the overall
grade is the worst category rather than the mean, suppressed findings do not
count, and more findings never improve the score. A failure there means the
model changed and should be declared, not that something is broken.

**This is not D5.** Pinning an uncalibrated number does not calibrate it.
These prove the scale is *stable*. What establishes it is *correct* is D17,
which scores the scale against a corpus carrying both well-maintained code and
applications written to be vulnerable. Both are needed, and neither
substitutes for the other: D17 could pass while the scale silently drifted
between releases, and these pins could pass on a scale that ordered the two
populations at random.

## D15 — A scanner's severity is not a measure of consequence

**Status.** Accepted, 2026-09-11.

**Question.** Four separate problems were solved, or attempted, on the
assumption that a finding's `severity` says how dangerous it is. All four
failed the same way, and it took measuring them side by side to see they
were one problem.

| where | symptom |
| --- | --- |
| the score | Django graded F; the number tracked how talkative Bandit is |
| triage tiers | `B105` produced **0** useful hits in 22 across the corpus |
| a proposed severity floor | cannot separate httpx from a planted-vulnerability repo |
| proposed default gates | `critical`-only catches nothing; `critical`+`high` fails half of good code |

**What the field actually encodes.** A scanner's severity answers *"how
confident am I that this pattern is present and matters in general"*, not
*"how bad is this in your code"*. Bandit rates SQL injection **medium** and
`hashlib.md5` **high**. Every mechanism built on top of the field inherits
that, and each rediscovery looked like a fresh problem.

**The evidence, from the examined corpus and four controls.**

Six candidate rules for a severity floor. None separates:

| rule | corpus trips | vulnerable controls caught |
| --- | ---: | ---: |
| `sev>=HIGH` | 5/10 | 2/4 |
| `sev>=HIGH & conf=HIGH` | 3/10 | 2/4 |
| `top25` | 6/10 | 4/4 |
| `top25 & sev>=MEDIUM` | 5/10 | 4/4 |
| `top25 & sev>=HIGH` | 3/10 | 2/4 |

Anything catching SQL injection and `pickle.loads` — both rated *medium* —
also catches django, flask, jekyll, lodash and sinatra. A well-maintained
`httpx` carries one high-confidence HIGH finding; the deliberately
vulnerable 200k-line control carries two. `B324` (`hashlib.md5`) appears in
both: RFC-mandated digest authentication in one, an invented token function
in the other, identical signature.

Two candidate default gates, same wall:

| default | good repos failed | controls caught |
| --- | ---: | ---: |
| `fail_on_severity: ["critical"]` | 1/10 | **0/4** |
| `fail_on_severity: ["critical","high"]` | **5/10** | 2/4 |

**Decision.** Nothing may *rank consequence* by reading a scanner's
severity. Severity stays a weight in the score and a filter an operator can
configure — both are honest uses of "how confident is the tool" — but no
mechanism may claim to identify the dangerous findings from it.

**What works instead, measured.** `fail_on_new` — ratchet on regressions
rather than absolute state — does not read severity at all, and therefore
does not inherit the flaw. Through a full adoption lifecycle on a fixture
with pre-existing debt:

```
first run, no baseline      exit=1   (everything is new)
after --bump-baseline       exit=0   (debt accepted once)
SQL injection introduced    exit=1   <- the case severity gates miss
plus shell=True             exit=1
reverted                    exit=0
```

False positives are baselined once and never asked about again, which is
exactly the property a severity threshold cannot have.

**Not adopted as a default here.** The first run fails for every new
adopter, and choosing what a tool refuses to build on first contact is an
operator's decision rather than this register's. Recorded so the option is
argued from data when it is taken up.

**The consequence for design.** The only consequence-bearing signal in the
data is CWE Top-25 membership, which caught 4/4 controls — too broad alone
at 6/10 corpus trips, but it is the one input that is not the scanner's own
opinion. Anything future that needs to rank danger should start there, and
must be measured against both the corpus and known-vulnerable controls
before it ships.

---

## D16 — The grade is a density, and the gate is what catches a vulnerability

**Status:** Accepted · 2026-09-11 · supersedes the normalizer half of D5

**Context.** D5 recorded that `sqrt(LOC/1000)` was "an invented normalizer
with no corpus behind it", and the calibration study then showed what that
cost. Under it the ranking followed how *big* a repository is rather than how
much is wrong with it:

| repo | kLOC | weighted findings / kLOC | `sqrt` normalized |
| --- | ---: | ---: | ---: |
| django | 144.5 | 1.51 | **18.18** ← ranked worst |
| flask | 7.8 | **3.35** | 9.38 |
| fastapi | 23.8 | 1.60 | 7.81 |

Flask carried 2.2× Django's finding density and normalized at half the value.
Django sat fifth by density and first by penalty. Over the ten examined
repositories, Spearman correlation of grade against size was **−0.37**, while
correlation of density against size was **+0.12** — the number was tracking
size, which is the one thing the dampener exists to remove.

**Decision.** Divide by `LOC/1000` rather than `sqrt(LOC/1000)` — a straight
density, weighted findings per thousand lines of scanned code — and move the
grade slope from 0.5 to 1.5 with it. The two only mean anything together.

**Why 1.5.** It is the slope that holds D5's calibration target across the
examined corpus. Four normalizers were measured on the same pinned run:

```
  sqrt,   slope 0.5    median 3.36 (B)   F=2   spread 5.00
  linear, slope 0.5    median 4.40 (A-)  F=0   spread 1.67
  linear, slope 1.2    median 3.56 (B+)  F=1   spread 4.02
  linear, slope 1.5    median 3.20 (B)   F=1   spread 5.00   <- adopted
```

Linear at 0.5 compresses everything into A− and cannot discriminate. 1.5 keeps
the median in the B band and the full 0-to-5 spread, and fixes the ordering:
Spearman(LOC, grade) moves **−0.37 → +0.02**, and the worst-ranked repository
becomes the densest one rather than the largest one.

**The cost, stated rather than discovered later.** A large repository with a
handful of serious findings scores *better* than it did. Measured on a control
built for this — 135,841 lines of benign Python plus one module carrying SQL
injection, `shell=True`, `pickle.loads`, MD5 and `eval`, seven scored findings
in all:

```
old model (sqrt, slope 0.5)    3.86  B+
new model (linear, slope 1.5)  4.71  A
```

A single HIGH finding in a 100,000-line repository now grades 4.91 — A+. That
is arithmetically correct for a density and useless as an alarm. Note that the
old model called the same control B+, so this is a worsening of a number that
was never safe rather than the loss of one that was.

It is accepted because **the grade was never what catches a vulnerability**,
and pretending otherwise is what made it dangerous. On that same control, all
three of the things that do catch it fire — this is the actual output, not a
description of intent:

- the **work order** puts all seven in §FIX, `B602` first, each with file and
  line;
- the report header reads ``**Worst category:** `code_vulnerabilities` ``;
- the run exits `gate FAIL` on the default `fail_on_new` (D15).

A grade compresses a repository to one number so it can be compared against
another repository and against itself last week. D15 already established that
no severity-derived threshold can rank consequence; this records the
corresponding limit on the score. `docs/scoring.md` now says so in the worked
example, where the repository with a live SQL injection grades A−.

**Consequences.**

- Every grade the tool has ever emitted moves. Nothing in the wild consumes
  them yet, so no migration is provided and `history.jsonl` is left alone.
- `tests/integration/test_scoring_drift.py` passed unchanged through this,
  because every assertion in it was relational — `< 5.0`, `<= one`, "sorted
  descending" — and a relational assertion detects inversion, not drift. The
  model was re-tuned end to end and the drift test said nothing. Pinned
  values were added; that file's own docstring had promised them.
- `calibration/calibrate.py` carried its own `sqrt` divisor, its own `0.5`
  slope, and a flat per-category sum that predated rank-discount saturation.
  Its subtotal for Django read 488.06 against the product's 218.5. The
  divisor and slope are imported now and the saturation is pinned by
  `tests/unit/test_calibration_harness.py`.
- The study's headline line reported the median over all fourteen corpus
  repositories, six of which no scanner can read. That reported 4.58 where
  the examined set sat at 3.20 — P7 broken inside the study that exists to
  check the scale. It now reports the examined median and names the
  exclusion.

**Still open at the time — closed by D17.** The letter bands were still
borrowed from `maintainability-agent` without their own study. D17 gives them
one, and the answer is partly negative: two edges are measured and three bands
hold no observation at all.

---

## D17 — Calibrated against both populations; `secrets` is a count, and three bands are unmeasurable

**Status:** Accepted · 2026-09-11 · amends D16 · **closes D5**

**Context.** D16 fixed size bias and I checked it against the only corpus
there was — fourteen well-maintained OSS projects. `corpus.json` had stated
the flaw in that from its first version: *"these are all well-maintained OSS
projects with their own security processes. The distribution measured here is
cleaner than the population this tool will actually be pointed at."*

A scale with no bad end cannot be calibrated. There is nothing to place D and
F against, and D5's band question had been open for that reason since
2026-09-08.

**Decision, part one: the corpus gets a bad end.** Five applications written
to be vulnerable are pinned alongside the maintained half and tagged
`kind: vulnerable-by-design` — OWASP PyGoat, NodeGoat, railsgoat, WebGoat and
Juice Shop. They are cloned and read; none is ever executed. WebGoat is
included precisely because it stays **unexamined**: D12 records that no
offline SAST in the floor reads Java, and a deliberately-vulnerable Java
application reporting a clean score is the sharpest demonstration available of
why coverage is reported beside the grade and never folded into it.

Two measures come with them. **AUC** is the probability that a maintained
repository outscores a vulnerable-by-design one — 1.00 is perfect ordering,
0.50 is a coin toss. **Separation** is the worst maintained grade minus the
best vulnerable one; negative means the populations overlap and *no* band
table can tell them apart.

**What the anchors immediately showed: D16 had made it worse.**

```
                        AUC    separation
sqrt everywhere         0.91      -0.58
linear everywhere (D16) 0.80      -3.76
```

Juice Shop carries four hardcoded API keys and three private keys and graded
**B+**, while Flask — which has no secrets at all — graded **F**. I had
recommended the density change without this evidence, because the evidence did
not exist. It does now.

**Decision, part two: `secrets` is a count, not a rate.** Seven committed
credentials divided by 115,340 lines is how a training application built to be
insecure outscored a well-run library. A committed private key is one
committed private key whether the repository is a thousand lines or a million.
`secrets` normalizes by `sqrt(LOC/1000)`; every other category keeps the
straight density D16 established. Damped, not exempted — an absolute count
failed Django on two low-confidence hits:

```
variant                     AUC    separation   Spearman(LOC, grade)
linear everywhere (D16)     0.80      -3.76            +0.14
sqrt everywhere (pre-D16)   0.91      -0.58            -0.32
linear; secrets absolute    0.90      +0.00            -0.24
linear; secrets sqrt        1.00      +0.65            -0.01   <- adopted
```

The slope moves 1.5 → 1.3 with it. Slope cannot reorder anything, so it is
chosen on where the median lands and how much of the corpus clamps at 0.0 and
loses its tail. 1.3 is the largest slope keeping the maintained median inside
the B band while the populations stay apart.

**A mapping defect found by the same run.** Flask's F was partly doubles.
Bandit's `B102` (`exec`) was mapped to **CWE-78** — *OS* command injection,
the shell weakness `B602` covers — and `B307` (`eval`) had no curated entry so
it inherited the same wrong CWE from Bandit itself. Corroboration merges
across scanners on a shared CWE, so `B102` and this project's own
`sca.python.eval` never merged and one `exec(compile(...))` line scored twice.
Both are now CWE-95, matching the convention semgrep, RuboCop and the built-in
rules already used. `is_top25` follows the documented ChildOf relationship to
CWE-94 so that describing the weakness accurately is not what removes its
Top-25 weight.

**The result, measured on the pinned corpus.**

| | value |
| --- | ---: |
| AUC (maintained above vulnerable) | **1.00** |
| separation | **+1.26** |
| maintained median | **3.41 (B)** — D5's target |
| vulnerable median | **0.00 (F)** |
| Spearman(LOC, grade) | **−0.05** |

All four examined vulnerable-by-design applications grade F. The maintained
half spans D to A+.

**Decision, part three: three bands cannot be calibrated, and saying so is the
closure.** Testing every edge against the distribution rather than assuming:

- The **D/F edge at 1.00 falls inside the population gap** (0.00 → 1.26). This
  is the one edge that carries a decision, and it is measured.
- The **centre is measured**: well-maintained code medians at 3.41, in B.
- **A−, B and C contain no observation at all.** Nine bands cannot be
  supported by ten maintained repositories, and no larger corpus fixes it,
  because at that end of the scale the difference between two repositories is
  five findings versus eight in twenty thousand lines. No ground truth says
  one of those deserves A and the other A+.

So the band edges above D/F are **presentational granularity, not measured
thresholds**, and this register now says so. A B+ is not meaningfully better
than an A−. Reading the letter as though it resolves that finely is the
failure mode, and it is the same one D15 and D16 describe from other angles:
the score is second class. The work order is the product.

**Consequences.**

- `calibrate.py` reports the two populations apart, with AUC and separation,
  and refuses to print a pooled median — which would describe neither.
- The corpus is 19 repositories; a run is roughly six minutes.
- Cloning deliberately-vulnerable applications is now part of re-running the
  study. They are training material, they are never executed, and
  `calibration/.corpus/` is gitignored and excluded from the self-audit.
- **D5 is closed.**

---

## D18 — Our output is never our input; a variable reference is not a credential

**Status:** Accepted · 2026-09-11 · two precision defects reported from two repositories on one day

### Part one — stored analysis output is not source

`cli._own_artifacts` removes the paths the current run is about to write. That
already fixed the obvious case: an audit had scored the report it produced —
446KB of quoted findings, in which gitleaks duly found a "secret" at line
11,529.

It cannot see a **copy** kept somewhere else, and two independent reports of
that arrived on the same day:

- this repository scanned `calibration/.corpus`: fourteen cloned third-party
  projects, 556,808 LOC, 550 findings, all about code that is not ours;
- `maintainability-agent` scanned `tools/validation/reports/`: 957,219 LOC of
  stored audit output *about other repositories*, 4,929 findings, which
  **diluted five genuine criticals to an A−**.

A stored report is the worst possible input. It quotes findings verbatim —
snippets, redacted secrets and all — so it manufactures findings about
findings, and it inflates the LOC denominator that decides the grade at the
same time. Both halves of the error push in the same direction.

**Decision.** Every default output filename is excluded by default, anywhere
in the tree, plus the `.secure-code/` and `.maintainability/` state
directories. The patterns are *derived from* `DEFAULT_OUTPUTS` rather than
written out, so adding an output cannot leave a file this tool writes readable
by the next run; `tests/unit/test_output_is_never_input.py` enforces that
structurally, per the standing rule that an identified bug class ships a check
that blocks its recurrence.

**The deliberate limit.** `vendor/`, `third_party/` and their kin are **not**
excluded. Vendored code is deployed code, and hiding it by default would
suppress real vulnerabilities in precisely the place nobody is reading.
Stored analysis output is not code at all; that distinction is the whole
basis of this decision, and widening it to "things that are not really ours"
would give away the thing the tool is for.

An operator with reports under a path we cannot guess still has to configure
it — which is what MA did.

### Part two — a variable reference is not a credential

`gitleaks.curl-auth-user` fires CRITICAL on `curl -sS -u "$SONAR_TOKEN:"` in a
GitHub Actions workflow. No credential is present: `$SONAR_TOKEN` is how you
write *not* putting one there, and it is the recommended idiom. Five
occurrences on one repository. Reproduced here from a clean fixture, where
this machine's own pre-commit hook blocked the commit — a third independent
confirmation.

**This became more expensive the same day.** D17 made `secrets` count-like, so
one false critical now costs roughly two grade points on a 100,000-line
repository where it previously cost two tenths. Raising a category's weight
raises the cost of being wrong in it; this is the matching precision work, and
it should be read as part of D17 rather than separately.

**Decision.** A `secrets` finding whose source line holds a variable reference
and no literal credential is demoted to **§REVIEW**, with the reason stated in
the work order.

It reads the file, because gitleaks runs with `--redact` and the variable name
is exactly what got redacted — the message reads `curl -sS -u REDACTED`, so
the distinction is not recoverable from the finding alone. `verify._is_silenced`
already reads source back for a different question.

**Conservative in both directions, deliberately.**

- **REVIEW, never ACCEPT.** The finding stays in the work order, stays in the
  report, and still escalates through `fail_on_category: [secrets]` from any
  axis. Demotion reorders it; it does not silence it.
- **A reference plus a literal is still a leak.** `curl -u "$USER:hunter2Passw0rd"`
  is untouched. Half a line done correctly must not launder the other half.
- **Unreadable means unchanged.** A missing file, a line past the end, a
  directory, or a finding out of git history whose line the working tree no
  longer has — every one of those leaves the finding in §FIX. Absence of
  evidence is not evidence of a reference.

**Known miss, stated.** The literal test is the same dull shape
`_looks_like_a_credential` uses — twelve or more characters with a digit and
an uppercase letter — so an all-lowercase hex token such as `a3f9c2b1d4e5` is
not caught, and a line carrying both it and a variable reference would be
demoted to REVIEW. The error falls in the safe direction and the finding
remains visible.

**One note on how it was nearly shipped broken.** The first literal test was
`[A-Za-z0-9+/_-]{12,}`, which matches `//sonarcloud` inside
`https://sonarcloud.io/api` — `/` and `+` are base64 alphabet and every URL is
full of them. Every `curl` line carries a URL, so the demotion would never
have fired on the one case it was written for. The parametrized test caught it
on the first run.

---

## D19 — `scoring_model`: the instrument says when it changed

**Status:** Accepted · 2026-09-11 · schema v2 · agreed with the `maintainability-agent` maintainer

**Context.** D16 and D17 changed what a `condition` number means without
changing the shape of the document carrying it. MA stores that number in its
scan history, and nothing in the document let it tell the two models apart —
same schema, same fields, a different number for the same repository. MA's
D155 closed it by keying trend comparability on our **release version**.

That works and is far too broad. It opens a new series on *every* release of
this tool, including ones that change no scoring at all, and a signal that
fires constantly teaches people to ignore it. Documenting the noise in a
changelog is documenting a defect rather than closing it.

**Decision.** A top-level `scoring_model` integer, and `schema_version` 2.

- **Top-level, not inside `producer`.** `producer` says *who*; this says *what
  model*. A consumer keying on it should not reach through an identity block.
- **An integer, not a version string.** The only question is "same or
  different". An integer cannot be padded, compared as text, or read as
  ordering that means more than it does.
- **v2 is v1 plus one field.** Every v1 key keeps its name, type and meaning.

**Where the line falls.** Bump when a repository's condition could differ for
a reason that is not the repository: the normalizer, the slope, any weight
table, the letter bands, the rank discount, `COUNT_LIKE_CATEGORIES`, the
scanner floor, or the built-in rule profile (D10). Do not bump for
documentation, adapters, CLI flags, output formats, performance, or a parser
fix that does not change which findings are produced.

**A new rule bumps it, and that was the arguable case.** MA proposed exempting
rules that "only add findings without rescoring existing ones". That resolves
the other way by MA's own criterion: a repository containing
`yaml.unsafe_load` scores lower the day that rule ships, with no change to the
repository. Adding findings *is* rescoring, because the score is a function of
the finding set, and a user must not read "we can see more now" as "your code
got worse". D10 already gives the rule profile an id, a version and a digest,
so this half is identifiable rather than hand-waved.

**1 is reserved and is never emitted.** It denotes every release before the
field existed, and those releases do not share one model — the corroboration
merge, the rank discount and D16 all moved the numbers. A v1 document omits
the field and MA keys it on the release version, which fragments those
correctly. Nothing may back-fill a 1.

**A hand-maintained integer is a defect waiting to happen, so it is
enforced.** This project has already shipped exactly that: `pyproject.toml`
said 0.4.0 while `__version__` said 0.3.0, and the release verified the half
that was right. Here the failure is the invisible kind — every field still
validates while MA splices two models into one line.

`test_scoring_drift.py` therefore digests the weight tables, the bonus, the
slope, the letter bands, the count-like categories **and the output of the
real `score()` over a fixed matrix**, and pins that digest to `SCORING_MODEL`.
Constants are digested for a legible failure; the outputs are digested because
a formula can change with no constant moving — `normalize()` did exactly that
today. Both mutations were tested against the check before it was trusted:
changing `GRADE_SLOPE` and changing the normalizer's exponent each fail it.

Adding a digest row is how a model change is declared. Editing an existing row
is redefining what that number meant, which is a lie a reviewer can see.

**Rollout, and why there is no deadlock.** MA's reader accepts v1 and v2 and
keys on `scoring_model` when present, the producer version when absent. So
MA's reader lands first and nothing breaks while this tool still emits v1;
this tool then ships v2 whenever it is ready. Neither release blocks the
other — which is better than the strict ordering D18 recorded, and D18's rule
still governs any future bump where a consumer cannot fall back.

The v1→v2 transition itself breaks the series once, because the key changes
shape. That break is honest: it is the boundary where the instrument's
self-description changed, and it happens once.
