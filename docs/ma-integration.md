# maintainability-agent integration

> Status: **v0.12.1 — 2026-09-11.** The `security-pillar.json` contract, schema v2.

`maintainability-agent`'s [ADR 007](https://github.com/marshallguillory86/maintainability-agent/blob/main/docs/adr-007-pillars-and-practice.md)
§1 declares Security a **`DELEGATED`** pillar naming this tool, and reports it
as `NotApplicable` so that a reader never mistakes silence for safety. This
document is the other half: the artifact that makes that entry unnecessary.

Settled in [D3](decisions.md): **this tool writes the artifact, MA reads it.**
MA does not execute `secure-code-agent`. That keeps MA's analysis free of
network access and tool acquisition, and keeps this tool's trust boundary —
including [D1](decisions.md) — out of MA's.

## Producing it

```bash
secure-code-agent . --config secure-code-agent.json \
  --fail-on-gate \
  --security-pillar security-pillar.json
```

Standalone use is unaffected. Without the flag nothing is written and every
other output is identical.

## Consuming it

```bash
maintainability-agent . --security-pillar security-pillar.json
```

## The contract

```json
{
  "schema": "secure-code-agent/security-pillar",
  "schema_version": 2,
  "scoring_model": 2,
  "producer": { "tool": "secure-code-agent", "version": "0.10.0" },
  "generated": "2026-09-09T20:00:00Z",
  "pillar": "security",
  "scope": "owned",
  "practice": {
    "level": 4,
    "summary": "gates — CI holds a security line that can be crossed",
    "signals": [
      { "signal": "CI runs secure-code-agent", "path": ".github/workflows/ci.yml" },
      { "signal": "CI enforces --fail-on-gate", "path": ".github/workflows/ci.yml" }
    ],
    "caps": []
  },
  "condition": 5.0,
  "condition_letter": "A+",
  "posture": "healthy",
  "verified_grade": "A+",
  "evidence_status": "complete",
  "evidence_reasons": [],
  "coverage": {
    "status": "complete",
    "scanners_run": ["bandit", "gitleaks"],
    "scanners_missing": []
  },
  "findings_by_severity": { "high": 2 },
  "reported_not_scored": {
    "test_tree":    { "count": 0, "loc": 4436, "worst_severity": null },
    "dependencies": { "count": 16, "loc": null, "worst_severity": "high" }
  },
  "loc_scanned": 12400
}
```

## Four invariants MA can rely on

**1. `practice` and `condition` are never averaged.** ADR 007 §2. They answer
different questions — whether anything *prevents* the next vulnerability, and
what the scanners *found*. No field in the document offers their mean, and
`test_the_pillar_never_averages_its_two_axes` parses the module and refuses a
function that would produce one. It is the same guard MA keeps over
`_pillars.py`.

**2. `condition` is `null` whenever the evidence cannot support it** — never
zero, never a default. This tool's failure mode is sharper than MA's: the score
is a rate over findings, so removing scanners removes findings and the number
goes **up**. On one tree, disabling them moved it from 0.00/F to 5.00/A+. A
`null` here means *"nothing measured"*, and a consumer must not substitute a
number for it.

**3. `posture` uses MA's matrix, cell for cell.** `HIGH_PRACTICE = 3` and
`GOOD_CONDITION = 3.5`, copied by value from `_pillars.py`. If MA moves either
threshold, `test_posture_matches_mas_matrix` fails here and the two tools get
reconciled rather than drifting into disagreeing about the word "healthy".

| | Poor condition | Good condition | Not measured |
| --- | --- | --- | --- |
| **Practice ≥ 3** | `managed debt` | `healthy` | `unverified` |
| **Practice < 3** | `unmanaged debt` | `unverified` | `unverified` |

A perfect practice level with no evidence is `unverified`, never `healthy` — a
maturity level may not vouch for code nobody looked at.

**4. Every practice signal names the file that proves it.** A maturity level a
reader cannot check is a grade with no marking scheme, and this one is a
judgment about someone's engineering practice made from the outside.

## The practice rubric

MA's rubric, its five level definitions and its `MAX_WITHOUT_CI` cap, read for
security. Read from **configuration and CI, never from source** — a scan says
the code is clean today; it cannot say whether anything stops tomorrow's merge
from committing a private key.

| Level | Meaning | Security evidence |
| --- | --- | --- |
| 1 | Nothing detectable | No scanner configuration, no security job in CI |
| 2 | Intent | Scanner configuration exists, but nothing runs it |
| 3 | Enforcement | CI runs a security scanner; a bad change can fail a build |
| 4 | Gates | CI holds a line — required scanners, a severity ceiling, a finding cap |
| 5 | Discipline | Gates plus a disclosure policy, expiring suppressions, pinned versions |

**Configuration without CI is capped at 2**, and a capped level says so in
`practice.caps`. A repository can hold every scanner config ever written,
declare every threshold in it, and still merge anything: a threshold nothing
evaluates is not a gate.

## What sits outside the score

`reported_not_scored` carries axes that are real findings and the wrong thing
to average into a code-condition grade. Both are measured, both are reported,
neither moves `condition`.

- **`test_tree`** — the repository's own tests. Including them moved the
  calibration corpus median from 4.36 to 50.15 and put ten of fourteen
  well-maintained projects at F. `secrets` are the exception and *do* score,
  because a committed credential is a leak wherever it lives.
- **`dependencies`** — advisories against a lockfile. Still **gated**: a
  critical runtime CVE fails a build exactly as before. Only the code-condition
  grade stops absorbing them.

See [`calibration.md`](calibration.md) for the measurements.

## Versioning

`schema_version` is **2**. v2 is v1 plus `scoring_model`; every v1 key keeps
its name, type and meaning.

**Any shape change bumps it, additions included.** This paragraph previously
read "a field may be added without a bump", and that was wrong in the
direction that costs a consumer silently: MA validates the document and
reports *no delegated pillar* rather than a partial one, so a v1 document
that grew a field would be refused with nothing on either side saying why.
`tests/unit/test_pillar_contract.py` pins every key and type so an addition
cannot land without this decision being taken.

**A bump is a two-repository release, in order:** specify the shape, MA lands
a reader accepting both versions, *then* this tool emits the new one. v2 was
cut that way — MA's reader accepts v1 and v2 and falls back to
`producer.version` when `scoring_model` is absent, so neither release blocked
the other.

`scoring_model` is an integer naming the scoring model that produced
`condition`. A delegated pillar can change its scoring model **without**
changing its schema — D16 and D17 did exactly that — and MA keys trend
comparability on this field, so a repository's condition is never compared
across a model change. It is pinned to a digest of the weights, the slope, the
bands and the real `score()` output, so the model cannot move without it.
`1` is reserved and never emitted: it would denote every release before the
field existed, and those do not share one model.

`producer.version` records which build produced the document. It is
load-bearing rather than decorative — it is the trend key for any v1 document
— and is held to `__version__` by `test_pillar_contract.py` after drifting
once and stamping `0.3.0` into every artifact a v0.4.0 wheel produced.

## What this does not do

- **MA does not run this tool**, and this tool does not import MA. Two
  independently releasable packages, which is the property MA's
  [ADR 008](https://github.com/marshallguillory86/maintainability-agent/blob/main/docs/adr-008-translation-and-decision.md)
  protects when it refuses a combined MCP server.
- **No shared library.** MA's constants are copied by value with a test
  asserting agreement, not imported. A dependency edge between the two would
  make them releasable only together.
- **The condition scale is not yet calibrated** ([D5](decisions.md)). MA's is
  calibrated so the mature-OSS median lands at 4.0; ours is not there yet, and
  a consumer should treat `condition` as a relative signal rather than an
  absolute one until it is.
