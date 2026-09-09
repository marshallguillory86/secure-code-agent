# Calibration study — 2026-09-09

The study [D5](decisions.md) has owed since 2026-09-08. The letter bands were
borrowed from `maintainability-agent` without its calibration study, and the
`sqrt(LOC/1000)` dampener is an invented normalizer with no corpus behind it.

Method, corpus and harness: [`calibration/`](../calibration/README.md).
Raw data: [`calibration/results.json`](../calibration/results.json).

## Result in one line

**The bands are approximately right and the inputs are wrong.** As the tool
runs today, ten of fourteen well-maintained open-source projects score **F**.
Excluding test directories and dependency findings — changing no weight, no
band and no slope — puts the corpus median at **3.10, a B**, which is the
target `maintainability-agent` calibrated to.

## What was measured

Fourteen repositories pinned by commit, spanning Python, JavaScript, Go, Ruby
and Java, and 7,764 to 465,033 LOC. Each audited through the real CLI with one
shared config and a fixed ten-scanner set.

| repo | lang | LOC | findings | score |
| --- | --- | ---: | ---: | --- |
| django | python | 465,033 | 1352 | 0.00 **F** |
| flask | python | 14,361 | 1139 | 0.00 **F** |
| requests | python | 10,249 | 715 | 0.00 **F** |
| httpx | python | 24,259 | 1389 | 0.00 **F** |
| fastapi | python | 104,938 | 5153 | 0.00 **F** |
| express | javascript | 17,980 | 93 | 0.00 **F** |
| axios | javascript | 55,211 | 66 | 0.00 **F** |
| lodash | javascript | 48,142 | 159 | 0.00 **F** |
| gin | go | 20,855 | 14 | 0.00 **F** |
| sinatra | ruby | 20,894 | 18 | 0.00 **F** |
| jekyll | ruby | 23,490 | 10 | 3.07 B |
| logrus | go | 7,764 | 4 | 4.66 A |
| commons-lang | java | 190,344 | 7 | 4.39 A- |
| gson | java | 50,871 | 4 | 5.00 A+ |

Median reported score **0.00**. Median *unclamped* score **−20.08** — the
middle of the corpus sits twenty points below the bottom of the scale.

## Why it fails, and it is not the bands

`category_grade` clamps at 0, so every F above is the same F. Recomputing
without the clamp shows the real spread: `worst_normalized` runs from 0.00 to
375.14, and grade 0 begins at 10. **The median repository is five times past
the floor.** No choice of band edges rescues that; the scale is saturated.

More damning, the ordering is not a security ordering. Sorted worst-first it
reads Python → JavaScript → Go/Ruby → Java, which is the order of **how
talkative each language's scanner is at low severity and low confidence**, not
of how safe the code is. Django, one of the most security-conscious projects in
Python, is bracketed with the noisiest.

This is `maintainability-agent`'s 0.5.0 lesson in a new form. There, absolute
finding counts graded repository *size*. Here, raw finding counts grade
*scanner verbosity per language*.

## The two inputs that actually move it

Every finding was already captured, so the input questions were answered from
the same evidence rather than by re-scanning — `calibrate.py --variants`
reproduces this table.

| input rule | median `worst_normalized` | median grade |
| --- | ---: | --- |
| as-run | 50.15 | 0.00 **F** |
| drop LOW severity | 22.63 | 0.00 **F** |
| drop dependency findings | 14.30 | 0.00 **F** |
| **drop test directories** | **4.36** | **2.82** B− |
| **drop tests and dependencies** | **3.81** | **3.10 B** |

Test directories are worth more than everything else combined, and severity
thresholds — the obvious knob — are worth the least.

**Test fixtures.** 696 of `requests`' 715 findings are in `tests/`; 90 of
`express`' 93. They are `B105`/`B106` hardcoded passwords, `B101` asserts —
test doubles, behaving exactly as test doubles do.

**Dependency findings.** 154 of `lodash`' 159 are CVEs in `package-lock.json`;
54 of `httpx`' 85 and 45 of `flask`' 68 are dependency advisories. These are
*true positives* — the question is not whether they are real but whether a
library's dev-dependency CVEs should sink its code-security grade.

**A third, smaller effect.** With tests excluded, Django still carries 107
`B703`/`B308` findings — `mark_safe`, which is Django's own template-escaping
API, flagged in the framework that defines it. FastAPI carries 107 `B101`
asserts in non-test source. Framework-idiomatic and stylistic rules survive
into the score at full weight.

## What this does not settle

Two product decisions, and the study deliberately stops at naming them:

1. **Do test directories count?** Worth a median of 50.15 → 4.36. Test trees do
   sometimes hold real secrets, so "exclude them" is not obviously right — but
   as things stand a project is graded largely on its test fixtures.
2. **Do dependency vulnerabilities score like source vulnerabilities?** Worth
   4.36 → 3.81, and the difference between `lodash` being F and being gradable.

Once both are answered the slope needs **no change**: the median lands at 3.10
under the current `×0.5`, inside the B band. That is the study's most useful
result — the arithmetic was never the problem.

## Limits of this study, stated

- **Corpus bias.** Fourteen well-maintained OSS projects with their own
  security processes. A median calibrated to earn a B here means "as clean as a
  well-run OSS project", not "average code". `maintainability-agent` has the
  same limitation.
- **Not exactly re-runnable.** Semgrep ran in its default online mode, so the
  registry rules are not pinned and a later run will differ for reasons
  unrelated to the code. Re-running with `scanners.semgrep.online: false` would
  pin the rules to `sca-offline@1.1.0` at the cost of breadth. Which mode the
  scale is calibrated *for* is itself unsettled: bands chosen from an online run
  do not fit an offline one, because offline finds less.
- **Shallow clones.** `--depth 1`, so gitleaks sees one commit rather than full
  history. Uniform across the corpus, but it understates secret findings.
- **Fourteen is small.** Enough to show saturation, not enough to place a band
  edge precisely.

## Status

D5 stays **open**. The method now exists, has been run, and has produced a
specific answer: the scale cannot be calibrated until the two input questions
above are decided, and the measured cost of each is recorded here. Choosing
bands before that would be fitting numbers to noise — which is the thing D5 was
raised to prevent.
