# Calibration study — 2026-09-10

> Status: **v0.11.1 — 2026-09-11.** The D5 calibration study, closed by D16 and D17.

The study [D5](decisions.md) has owed since 2026-09-08. The letter bands were
borrowed from `maintainability-agent` without its calibration study, and the
dampener was an invented normalizer with no corpus behind it.

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

**An earlier version of this section called these true positives. That was
wrong, and it is the error that kept the floor in place for a day.**

Checking that a construct is present is not checking that a defect is
present, and the two were conflated. Inspecting the actual matches:

- Django's `B105 hardcoded password` hits are `EMAIL_HOST_PASSWORD = ""` and
  `SECRET_KEY = ""` — **empty strings**, the framework's own defaults.
- Django's `B608 SQL injection` hits include
  `raise ImproperlyConfigured('Cannot determine PostGIS version for …')`, an
  error message containing no SQL, and
  `cursor.execute("SELECT %s, %s, %s FROM %s …")`, which is parameterised.
- Django's 56 `mark_safe` hits are the admin rendering its own escaped
  output, in the framework that *defines* `mark_safe`.

Some are genuine — Flask's `exec()` config loader, Django's `exec()` in
`commands/shell.py`, the MD5 in `auth/hashers.py`. Most are not. Reporting
them all as real defects and then reasoning about what F "means" was
answering the wrong question: a tool that grades Django, FastAPI, httpx and
Flask all F is measuring how talkative Bandit is on large Python codebases,
which is the exact failure D5 was raised to prevent.

The product already has the mechanism for that distance: a baseline, and
suppressions with a required note. What it does not have is a decision about
whether an *untriaged* run of a framework should read F. That is a product
decision, not an arithmetic one.

## What the correction bought, and what is still wrong

Repeats of one rule now saturate: sorted worst-first, the k-th hit of a rule
counts `weight / sqrt(k)`. One rule firing 56 times is one fact observed 56
times, not 56 independent defects. Distinct rules still add in full.

| repo | before | after |
| --- | --- | --- |
| httpx | 0.13 **F** | 2.58 B- |
| fastapi | 0.00 **F** | 2.47 C |
| requests | 2.54 B- | 3.98 B+ |
| flask | 0.00 **F** | 0.44 **F** |
| django | 0.00 **F** | 0.00 **F** |

Repositories at F: four, then two. No repository scored lower. Median 4.48.

**The first attempt at this broke P3 and the tests caught it.** Scoring a rule
as `mean(weight) * sqrt(n)` is also saturating, and under it one CRITICAL plus
nine LOW hits of one rule scored 6.88 against 15.0 for the CRITICAL alone —
deleting nine real findings would have *raised* the grade. The rank discount
cannot do that: the worst hit always lands at k=1 at full weight.

**A regression was found the same way.** Reading Bandit's CWEs silently
disabled the `mark_safe` de-duplication, because Bandit files B308 as CWE-79
and B703 as CWE-80 and the merge key preferred the CWE over the alias table.
Django went back to counting `mark_safe` twice. Every unit test passed
throughout — they all used rules with no CWE — and the corpus caught it.

### What was wrong: the normalizer — resolved, see D16

Django and Flask remained at F, and the cause was isolated here. Under
`sqrt(LOC/1000)`, **the largest repository in the corpus ranked worst**:

| | kLOC | sqrt-normalized | per-kLOC |
| --- | ---: | ---: | ---: |
| django | 145.5 | 15.53 (**F**) | 1.29 (A-) |
| flask | 8.3 | 9.12 (**F**) | 3.17 (B) |
| fastapi | 35.7 | 5.06 (C) | 0.85 (A) |

That is size bias — the precise thing the dampener exists to remove, and
which D5 already records as "an invented normalizer with no corpus behind
it". One HIGH finding costs a full grade point in an 8k-line repository and a
quarter of that in Django.

**It was not changed at the time, for three reasons.** It moves every grade
the tool has ever emitted. The slope would need recalibrating and this corpus
could not support that (below). And it weakens the gate: a synthetic
1,939-line repository carrying SQL injection, command injection,
`pickle.loads`, `yaml.load`, `eval`, MD5 and hardcoded credentials scored
0.00 F and would land near D under per-kLOC.

**All three were then answered, and the change was made — D16.** Corpus
coverage was fixed first (below), which made the slope recalibratable: four
normalizers were measured on one pinned run and `linear, slope 1.5` was the
one that held the D5 target. Nothing in the wild consumes a grade yet, so
"moves every grade ever emitted" cost nothing. The third reason was the real
one and it stands — the weakening is genuine, and it is why D16 records that
the gate and the work order, not the number, are what catch a vulnerability.

Re-measured over the same corpus after the change:

| | before (sqrt, 0.5) | after (linear, 1.5) |
| --- | ---: | ---: |
| examined median | 3.36 (B) | 3.20 (B) |
| Spearman(LOC, grade) | −0.37 | **+0.02** |
| worst-ranked repository | django (largest) | **flask (densest)** |
| spread | 0.00–5.00 | 0.00–5.00 |

**This was measured against a corpus with no bad end in it, and that mattered.**
Adding vulnerable-by-design anchors showed straight density had cost
discriminative power — AUC 0.91 → 0.80 — because it divided committed
credentials by repository size. D17 amends it: `secrets` normalizes by
`sqrt(LOC/1000)` and the slope is 1.3. The size-bias fix above stands; the
figures in this table are superseded by the result section at the end of this
document.

### Corpus coverage was the blocker, and fixing it answered the question

Six of the fourteen were scoring near-perfectly because they were
**unexamined**, not clean. Python repositories produced 712 to 5,107 real
findings each; everything else produced nought to four. Three orders of
magnitude, and none of it about those projects being thirty times cleaner
than Django.

**Two causes, and only one was structural.**

`njsscan` and `rubocop` were simply not installed on the machine running the
study, so JavaScript and Ruby had no scanner that reads them. Installing
both is all it took:

| repo | before | after |
| --- | --- | --- |
| axios | 5.00 A+ | 4.38 A- |
| lodash | 4.59 A | 4.48 A- |
| sinatra | 3.10 B | 2.79 B- |
| express | 5 findings | 90 findings |

Go and Java cannot be fixed that way, and [D12](decisions.md) already says
why: gosec analyses Go by invoking the target's *own* build tooling and
fails without the toolchain on the host; PMD covers none of the patterns and
SpotBugs needs compiled bytecode. `gin`, `logrus`, `gson` and `commons-lang`
are unreadable by this floor.

**Those four were holding the median up.** Their own median is 5.00 — four
perfect scores for repositories nobody looked at. The product refuses to
grade what it did not examine (P7); a study computing percentiles over
repositories in the same position is doing the thing the product refuses to
do. `summarize()` now reports the examined set separately and names what it
excluded.

| set | n | median |
| --- | ---: | --- |
| examined | 10 | **3.38** |
| unexamined | 4 | 5.00 |
| all fourteen | 14 | 4.37 |

**3.38 is in the B band, and the B band is the target.**
`maintainability-agent` calibrates so a mature-OSS corpus medians at a B.
This corpus already does, and the examined spread — 0.00, 0.44, 2.47, 2.58,
2.79, 3.98, 4.38, 4.48, 4.61, 5.00 — is a distribution rather than the cliff
it was that morning. **No band edge needs moving to achieve it.**

What remains is one repository rather than the scale: Django still reads
0.00, for the normalizer reason above.

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

**Closed — band edges, and what a grade means. See D17.** The blocker was
that this corpus had no bad end: every repository in it was a well-maintained
OSS project, so there was nothing to place D and F against. Five
vulnerable-by-design applications are now pinned alongside them (OWASP PyGoat,
NodeGoat, railsgoat, WebGoat, Juice Shop), cloned and read but never executed.

With both populations present the scale can be scored rather than admired:

| | value |
| --- | ---: |
| AUC (maintained above vulnerable) | **1.00** |
| separation (worst maintained − best vulnerable) | **+1.26** |
| maintained median | **3.41 (B)** |
| vulnerable median | **0.00 (F)** |
| Spearman(LOC, grade) | **−0.05** |

Two edges are measured: **D/F at 1.00 falls inside the population gap**, and
the centre lands in B. **A−, B and C contain no observation at all**, and no
larger corpus fixes that — at that end the difference between two
repositories is five findings versus eight in twenty thousand lines, and
nothing says one deserves A and the other A+. Those edges are presentational
granularity, not measured thresholds.

The old worry here — that the bottom of the distribution was frameworks being
graded on constructs they exist to provide — turned out to be two things. Part
was real (Django's `mark_safe`, Flask's `exec(compile(...))` in
`config.from_pyfile`), and the rank discount and triage tiers address it. Part
was a defect: Bandit's `B102`/`B307` were mapped to CWE-78, so they never
merged with the built-in `sca.python.eval` finding on the same line and one
defect scored twice. Flask carried four such pairs.
