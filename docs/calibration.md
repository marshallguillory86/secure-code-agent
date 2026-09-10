# Calibration study — 2026-09-09

The study [D5](decisions.md) has owed since 2026-09-08. The letter bands were
borrowed from `maintainability-agent` without its calibration study, and the
`sqrt(LOC/1000)` dampener is an invented normalizer with no corpus behind it.

Method, corpus and harness: [`calibration/`](../calibration/README.md).
Raw data: [`calibration/results.json`](../calibration/results.json).

## Result in one line

**The scale now discriminates, and it is still not calibrated.** Three input
fixes — separating the test tree, separating dependencies, and pinning Semgrep
to the offline profile — moved the corpus median from **0.00 (F)** to **1.87
(D)** and turned a two-cliff distribution into one that spans A+ to F. Band
edges still cannot be chosen: six of fourteen sit at the floor, and they are
all one language.

## Run of record — 2026-09-09, pinned

Fourteen repositories pinned by commit; one shared config; ten scanners;
Semgrep pinned to `sca-offline@1.1.0 (357b8d7e6652)` rather than the online
registry, so **this run is exactly reproducible** and P6 is met.

| repo | lang | primary LOC | findings | score |
| --- | --- | ---: | ---: | --- |
| django | python | 145,456 | 363 | 0.00 **F** |
| flask | python | 8,284 | 80 | 0.00 **F** |
| requests | python | 5,965 | 24 | 0.00 **F** |
| fastapi | python | 35,655 | 255 | 0.00 **F** |
| gin | go | 16,823 | 15 | 0.00 **F** |
| httpx | python | 7,585 | 92 | 0.13 **F** |
| sinatra | ruby | 7,135 | 8 | 1.49 D |
| jekyll | ruby | 14,590 | 17 | 2.25 C |
| axios | javascript | 26,788 | 17 | 3.19 B |
| lodash | javascript | 25,944 | 162 | 3.23 B |
| express | javascript | 4,497 | 3 | 5.00 A+ |
| logrus | go | 6,609 | 4 | 5.00 A+ |
| gson | java | 21,784 | 4 | 5.00 A+ |
| commons-lang | java | 97,561 | 4 | 5.00 A+ |

Median reported score **1.87 (D)**. Median unclamped **−1.33**, against −20.08
before any of this.

## What each fix was worth

| | median `worst_normalized` | median score |
| --- | ---: | --- |
| everything scored, Semgrep online | 50.15 | 0.00 **F** |
| test tree separated | 15.36 | 0.00 **F** |
| dependencies separated, Semgrep pinned offline | **12.65** | **1.87 D** |
| …and dependencies dropped entirely rather than moved | 6.26 | — |

`lodash` is the clearest single case: **0.00 F → 3.23 B**, because 154 of its
159 findings were CVEs in `package-lock.json` and now sit on their own axis
where they are still gated but no longer graded as code condition.

Dropping LOW severity is worth **nothing** at the median now. That noise was
overwhelmingly in the test tree and has already moved out of the score.

## What is left, and it is one language

Six repositories sit at the floor and five of them are Python. The residue is
Bandit at low severity and low confidence over primary source: `B101` asserts
in non-test code, and in Django's case 107 `B703`/`B308` findings for
`mark_safe` — the framework's own template-escaping API, flagged in the
framework that defines it.

That is a **finding-quality** problem, not a band-edge problem, and it is the
next thing to measure. Choosing thresholds while one language's scanner
dominates the bottom of the distribution would bake that scanner's verbosity
into the scale.

## Limits of this study, stated

- **Corpus bias.** Fourteen well-maintained OSS projects with their own
  security processes. A median calibrated to earn a B here means "as clean as a
  well-run OSS project", not "average code". `maintainability-agent` has the
  same limitation.
- **Reproducible, at the cost of breadth.** Semgrep is pinned to
  `sca-offline@1.1.0 (357b8d7e6652)`, so the run re-derives exactly — that is
  what P6 requires. The cost is real: the offline profile is 20 rules against
  the registry's thousands, so the corpus looks cleaner than an online run
  would show. **Bands chosen here do not transfer to an online run**, which
  finds more and would score lower. If the tool's default stays online, a
  second calibration is owed for that mode.
- **Shallow clones.** `--depth 1`, so gitleaks sees one commit rather than full
  history. Uniform across the corpus, but it understates secret findings.
- **Fourteen is small.** Enough to show saturation, not enough to place a band
  edge precisely.

## Status

D5 stays **open**, with both input questions now answered in code and the
method reproducible.

**Answered — test directories.** Separated, not excluded: the primary tree is
scored, the test tree reported beside it, and `secrets` findings score
wherever they live.

**Answered — dependencies.** Their own axis, still gated. A critical runtime
CVE fails a build; it no longer sinks a code-condition grade.

**Answered — which mode to calibrate.** Offline and pinned, so the study
re-derives. P6 is met.

**Still open — band edges.** They cannot be chosen while six of fourteen sit at
the floor and five of those are one language. The residue is Bandit's
low-confidence output over primary source, which is a finding-quality question
and the next thing to measure. Choosing thresholds now would bake one scanner's
verbosity into the scale, which is what D5 was raised to prevent.

**Still open — the target.** MA calibrates so the mature-OSS median lands at
**4.0**. This corpus medians at **1.87**. Closing that gap is a decision about
what a grade should mean, not an arithmetic adjustment.
