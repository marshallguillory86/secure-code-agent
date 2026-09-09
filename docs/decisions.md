# Decision register

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
| D3 | The MA Security pillar is fed by an artifact, not by MA executing this tool | 2026-09-08 | Accepted |
| D4 | A failing security audit fails MA's CI | 2026-09-08 | Accepted |
| D5 | The condition scale must be calibrated against a corpus before it is trusted | 2026-09-08 | Open — method needed |
| D6 | Scanner licences are judged by mechanism, not by name | 2026-09-08 | Accepted |
| D7 | The project declares a minimum tool floor, and defaults to it | 2026-09-08 | Accepted |
| D8 | Floor tools have a cadence; repository-level ones arrive by import | 2026-09-08 | Accepted |
| D9 | Our ruleset is the offline floor, bounded to language primitives | 2026-09-09 | Accepted |

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

**Consequence.** Two sources of truth remain, and this only aligns them by
hand. Generating the schema from the loader is still owed
([`architecture.md`](architecture.md) §3).

## D3 — The MA Security pillar is fed by an artifact

**Question.** `maintainability-agent` declares Security as a `DELEGATED` pillar
naming this tool ([MA ADR 007](https://github.com/marshallguillory86/maintainability-agent/blob/main/docs/adr-007-pillars-and-practice.md)
§1), but has no ingestion path. Should MA execute `secure-code-agent`, or
ingest an artifact it produces?

**Decision.** This tool writes `security-pillar.json`; MA ingests it via
`--security-pillar <path>`.

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

**State: open.** The method is owed, and it should follow MA's shape — a named
corpus, a measured distribution, bands chosen from it, and the study published
so the numbers can be argued with. Until then the scale is uncalibrated, and
anything consuming it (D3, D4) should treat it as such.

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
