# Calibration study — 2026-09-10

The study [D5](decisions.md) has owed since 2026-09-08. The letter bands were
borrowed from `maintainability-agent` without its calibration study, and the
`sqrt(LOC/1000)` dampener is an invented normalizer with no corpus behind it.

Method, corpus and harness: [`calibration/`](../calibration/README.md).
Raw data: [`calibration/results.json`](../calibration/results.json).

## Result in one line

**Most of the floor was our own bug.** The corpus median went from **0.00 (F)**
to **4.37 (A−)** across three rounds of fixes, and all but the last round were
defects in this tool rather than properties of the code it was reading. Four
repositories remain at F, every one of them on findings that were checked
individually and are **true positives**. Band edges are now a question about
what a grade should *mean*, not about arithmetic.

## Run of record — 2026-09-10, pinned

Fourteen repositories pinned by commit; one shared config; ten scanners;
Semgrep pinned to `sca-offline@1.2.0 (e861a891559f)` rather than the online
registry, so **this run is exactly reproducible** and P6 is met.

| repo | lang | primary LOC | findings | score |
| --- | --- | ---: | ---: | --- |
| django | python | 145,456 | 260 | 0.00 **F** |
| fastapi | python | 35,655 | 167 | 0.00 **F** |
| httpx | python | 7,585 | 35 | 0.13 **F** |
| flask | python | 8,284 | 20 | 0.15 **F** |
| requests | python | 5,965 | 21 | 2.54 B- |
| sinatra | ruby | 7,135 | 7 | 3.10 B |
| commons-lang | java | 97,561 | 8 | 4.15 A- |
| lodash | javascript | 25,944 | 7 | 4.59 A |
| jekyll | ruby | 14,590 | 6 | 4.61 A |
| axios | javascript | 26,788 | 5 | 5.00 A+ |
| express | javascript | 4,497 | 5 | 5.00 A+ |
| gin | go | 7,146 | 5 | 5.00 A+ |
| gson | java | 21,784 | 5 | 5.00 A+ |
| logrus | go | 2,964 | 5 | 5.00 A+ |

Median reported score **4.37 (A−)**. Median `worst_normalized` **1.27**,
against 50.15 when this study began.

## What each fix was worth

| | median score | at F |
| --- | --- | ---: |
| everything scored, Semgrep online | 0.00 **F** | 10/14 |
| test tree separated | 0.00 **F** | — |
| dependencies separated, Semgrep pinned offline | 1.87 **D** | 6/14 |
| documentation axis; secrets gated rather than force-scored | 1.34 **D** | 7/14 |
| **finding paths anchored to the audited tree** | **4.37 A−** | 4/14 |
| corroborating duplicates merged | 4.37 A− | 4/14 |

### The path bug was the largest single input error

Two defects in this tool, both fail-open, both silent:

**gitleaks reports repository-relative paths; every other scanner reports
absolute ones.** Every consumer that asks *"where is this?"* resolved a
relative path against the **process working directory** — wherever the
operator happened to invoke the CLI — so `relative_to(root)` raised and the
answer came back "no". Consequences:

- `exclude_patterns` **did not apply to gitleaks findings at all**. An
  operator excluding `vendor/` still had vendor secrets scored.
- Every gitleaks finding was scored as primary-tree regardless of where it
  lived. `requests` was held at F by four `tests/certs/*.key` files its own
  suite generates; `flask` by six documentation examples.

**`**/` did not include depth zero.** The pattern carries a literal `/`, so
`**/*_test.go` matched `router/context_test.go` and never `context_test.go`.
Gin keeps its tests beside the code they test, so three of its four
"production" secrets were root-level test fixtures. Gin went **F → A+**, and
its measured LOC fell from 16,823 to 7,146 once `testdata/` was recognised.

Both now ship a structural block:
[`test_finding_paths.py`](../tests/unit/test_finding_paths.py) anchors paths at
`Scanner._make_finding` — the one constructor every adapter passes through —
and asserts no adapter bypasses it.

### Two rules of our own were wrong

`sca.python.eval` matched `eval("literal")`. `sca.offline.ruby.code-injection`
matched `class_eval(&block)` — Ruby's **safe** form, where a proc is handed
over and nothing is ever parsed. Four of Sinatra's five code-injection
findings were that single expression; Sinatra went **F → B**.

Narrowing a rule changes its meaning, which under [D10](decisions.md) requires
a profile version bump. It did not get one, and nothing caught that, so
[`test_ruleset_version.py`](../tests/unit/test_ruleset_version.py) now pins the
ruleset digest to `PROFILE_VERSION`.

### Merging duplicates was worth nothing, and was done anyway

Bandit ships `mark_safe` as both `B308` and `B703`; Django carried 56 and 51 of
them sharing 50 lines. Merging changed **no repository's grade** — Django was
already clamped at 0 — and it is fixed because a report that lists one line
twice is wrong about the code, and a work order built from it asks for the
same fix twice. The second check is recorded as `corroborated_by` rather than
discarded: two scanners agreeing is stronger evidence, not weaker.

## What is left is not a bug

Four repositories remain at F. Every contributing finding was inspected.

| repo | normalized | dominant rule | share |
| --- | ---: | --- | ---: |
| django | 33.4 | `B703` `mark_safe` | 31% |
| fastapi | 20.3 | `B101` bare `assert` | 50% |
| httpx | 9.7 | `B101` bare `assert` | 76% |
| flask | 9.7 | `sca.python.eval` | 32% |

They floor at `normalized = 10`.

**None of these are false positives.** Django's `exec()` calls are in
`commands/shell.py`, its MD5 in `auth/hashers.py` and the SQLite `MD5()` SQL
function, its `mark_safe` in the framework that *defines* `mark_safe`. Flask's
`exec()` loads config from a Python file; its SHA-1 tags sessions. FastAPI's 81
bare `assert`s are bare `assert`s.

Django is graded F because **it is a framework whose job is to do dangerous
things safely**. That is the distance between *"contains dangerous
constructs"* and *"is insecure"*, and no amount of pattern-narrowing closes
it — the constructs really are there.

The product already has the mechanism for that distance: a baseline, and
suppressions with a required note. What it does not have is a decision about
whether an *untriaged* run of a framework should read F. That is a product
decision, not an arithmetic one.

## Two candidate adjustments, measured

Neither is adopted. Both are recorded so the choice is argued rather than
discovered.

| | median | at F |
| --- | ---: | ---: |
| as run | 4.37 A− | 4 |
| √n per rule (diminishing returns on repeats) | 4.56 A | 1 |
| drop LOW severity entirely | 4.80 A+ | — |

**√n per rule** treats 81 instances of one rule as one strongly-evidenced fact
rather than 81 independent defects. It is the only lever that moves the four
floored repositories — fastapi 0.00 → 3.41, httpx 0.13 → 3.10, requests 2.54 →
4.39 — and Django stays at F under it regardless.

It should not be adopted to reach a target, because **the target is already
met**: `maintainability-agent` calibrates so a mature-OSS median earns a B, and
this corpus medians at A−. √n would move it to A, further past the mark rather
than toward it. The argument for it has to be that repeated identical findings
are correlated evidence — which is a claim about what a rule count means, and
is arguable on its merits.

The real remaining distortion is **spread, not centre**: nine repositories sit
at 4.15 or better and four at 0.15 or worse, with almost nothing between. That
is a cliff produced by clamping a linear slope at zero, and it is a
slope-and-bands question.

## Limits of this study, stated

- **Corpus bias.** Fourteen well-maintained OSS projects with their own
  security processes. A median calibrated here means "as clean as a well-run
  OSS project", not "average code". `maintainability-agent` has the same
  limitation.
- **Untriaged.** No repository has a baseline or suppressions. This measures
  first-run output, which is the worst case by construction.
- **Reproducible, at the cost of breadth.** Semgrep is pinned to
  `sca-offline@1.2.0 (e861a891559f)`, so the run re-derives exactly — that is
  what P6 requires. The cost is real: the offline profile is 20 rules against
  the registry's thousands, so the corpus looks cleaner than an online run
  would. **Bands chosen here do not transfer to an online run.** If the tool's
  default stays online, a second calibration is owed for that mode.
- **Shallow clones.** `--depth 1`, so gitleaks sees one commit rather than full
  history. Uniform across the corpus, but it understates secret findings.
- **Fourteen is small.** Enough to show saturation, not enough to place a band
  edge precisely.
- **One language dominates the floor.** All four floored repositories are
  Python, which is also the language with the most talkative floor scanner.

## Status

D5 stays **open**, narrowed to one question.

**Answered — test directories.** Separated, not excluded: the primary tree is
scored, the test tree reported beside it and gated where the operator names
the category.

**Answered — documentation.** Its own axis, on the same terms.

**Answered — dependencies.** Their own axis, still gated. A critical runtime
CVE fails a build; it no longer sinks a code-condition grade.

**Answered — secrets.** No longer force-scored onto the primary axis. Nothing
static separates a live credential from a test certificate, so they are gated
from any axis rather than graded from all of them.

**Answered — which mode to calibrate.** Offline and pinned, so the study
re-derives. P6 is met.

**Answered — is the residue noise?** No. It was measured finding by finding
and it is true positives.

**Still open — band edges, and what a grade means.** The corpus median is
4.37 (A−) against MA's 4.0 target, so the centre is defensible. The
distribution is not: it is bimodal, and the four at the bottom are frameworks
being graded on constructs they exist to provide. Whether that is the right
answer, or whether an untriaged framework should read lower-but-not-F, is a
product decision.
