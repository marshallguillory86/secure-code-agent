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
