# Calibration

The method [D5](../docs/decisions.md) owed. It carried *"Open — method
needed"* from 2026-09-08 to 2026-09-11: the letter bands were borrowed from
`maintainability-agent` without its calibration study, and the dampener was an
invented normalizer with no corpus behind it.

**D5 is now closed**, by [D16](../docs/decisions.md) (the normalizer) and
[D17](../docs/decisions.md) (the two-population corpus, the `secrets`
exception, and what the bands can and cannot mean). This directory is how that
was measured, and re-running it is how any future change to the scoring model
is checked.

```
python calibration/calibrate.py                       # whole corpus
python calibration/calibrate.py --only flask,gin      # one or two
```

Results land in `results.json`; the study itself is
[`docs/calibration.md`](../docs/calibration.md).

## The three files

**`corpus.json`** — nineteen repositories pinned by commit, in **two
populations**.

Fourteen are `kind: maintained`: well-known, actively maintained projects,
selected to span the languages the floor actually reads and roughly two orders
of magnitude of size, because a corpus of similarly-sized repositories cannot
tell us anything about a size normalizer.

Five are `kind: vulnerable-by-design`: OWASP PyGoat, NodeGoat, railsgoat,
WebGoat and Juice Shop. Without them the corpus had no bad end, so there was
nothing to place D and F against and D5's band question could not be answered
at all — which is exactly where it sat, open, from 2026-09-08 to 2026-09-11.
They are cloned and read by the scanners and **never executed**. WebGoat is
here to stay *unexamined*: no offline SAST in the floor reads Java (D12), and
a deliberately-vulnerable Java application reporting a clean score is the
sharpest demonstration of why coverage is reported beside the grade.

The two are never pooled. `summarize()` reports each separately along with
**AUC** — the probability a maintained repository outscores a vulnerable one —
and **separation**, the worst maintained grade minus the best vulnerable one.
Negative separation means the populations overlap and no band table can tell
them apart.

**`calibration-config.json`** — one config for every repository. Without
`--config` the audit loads the *audited project's* own `secure-code-agent.json`
when it has one (release-blockers §7), and a corpus measured under two
different `exclude_patterns` is not a distribution. It lives outside every
audited tree, which is the operator artifact [D1](../docs/decisions.md)
supports.

It carries no explanatory keys, because the loader rejects keys it does not
read ([D2](../docs/decisions.md)) — a rule this file's first draft violated and
the tool correctly refused. Hence this README.

**`calibrate.py`** — audits each repository through the real CLI and
recomputes per-category subtotals from the findings.

## Five choices that move the result

Stated here so they can be argued with, rather than discovered in the numbers.

1. **Test directories are scanned, and scored on their own axis.** They are
   not excluded — the run still reports what is in them, and still gates on
   categories the operator names there. They simply do not grade the code
   condition, because a project graded on its test fixtures is graded on the
   wrong thing. Documentation is handled the same way. This is what the
   product does by default, so the corpus measures the product.

   Getting this wrong was the study's largest input error, twice: first by
   including test trees at all (median `worst_normalized` 50.15 → 15.36), then
   by anchoring finding paths so badly that the split silently did not apply
   to gitleaks (median score 1.34 → 4.37).
2. **`vendor/` and `target/` are excluded** on top of the defaults. Both hold
   third-party or generated code — Go vendoring, Maven output — and scoring a
   project on its dependencies' source measures the wrong thing. This is the
   only deviation from `DEFAULT_EXCLUDES`.
3. **No repository has a baseline or suppressions.** This measures untriaged
   first-run output, which is the worst case by construction. It is also why
   four frameworks sit at F on true positives they would ordinarily accept —
   see [`docs/calibration.md`](../docs/calibration.md).
4. **The distribution is computed over repositories a language scanner
   actually read.** The rest are measured, listed, and kept out — see
   "Unexamined is not clean" below.
5. **Scorecard and gosec are not in the scanner set.** Scorecard is
   repository-cadence and needs a GitHub token; gosec needs each project's own
   Go toolchain ([D12](../docs/decisions.md)). Including a tool that runs for
   some repositories and not others would put the difference into the
   distribution.

## Unexamined is not clean

**`njsscan` and `rubocop` must be installed for a valid run.** Without them
JavaScript and Ruby have no scanner that reads them, and the study cannot
tell a clean repository from an unread one.

```
pip install njsscan
gem install rubocop          # 1.28.2 is enough
```

The difference is not subtle. Before they were installed, Python
repositories produced 712 to 5,107 real findings each while JavaScript, Ruby,
Go and Java produced nought to four — three orders of magnitude, and none of
it about those projects being cleaner. Installing the two moved `axios`
5.00 → 4.38, `lodash` 4.59 → 4.48 and `sinatra` 3.10 → 2.79.

**Go and Java cannot be fixed this way, and that is [D12](../docs/decisions.md).**
gosec analyses Go by invoking the target's own build tooling and fails
without the Go toolchain on the host; PMD covers none of the patterns and
SpotBugs needs compiled bytecode. Four repositories — `gin`, `logrus`,
`gson`, `commons-lang` — are therefore unreadable by this floor.

They were still in the median, and they were holding it up. Their own median
is **5.00**: four perfect scores for repositories nobody looked at.

| set | n | median |
| --- | ---: | --- |
| examined | 10 | **3.38** |
| unexamined | 4 | 5.00 |
| all fourteen | 14 | 4.37 |

The product refuses to grade what it did not examine (P7). A study that
computes percentiles over repositories in the same position is doing the
thing the product refuses to do, so `summarize()` reports the examined set
separately and names the repositories it left out.

*(Those figures are from the 2026-09-10 run, kept because they are what
motivated the change. The current run is below.)*

## The result

Measured on the nineteen-repository corpus at the pinned commits:

| | value |
| --- | ---: |
| AUC (maintained scores above vulnerable) | **1.00** |
| separation | **+1.26** |
| maintained median | **3.41 (B)** |
| vulnerable-by-design median | **0.00 (F)** |
| Spearman(LOC, grade) | **−0.05** |

All four *examined* vulnerable-by-design applications grade F; the maintained
half spans D to A+. Two band edges are measured — D/F at 1.00 falls inside the
gap between the populations, and the centre lands in B. A−, B and C hold no
observation at all, and D17 records why no larger corpus fixes that.

## Why subtotals are recomputed rather than read

`category_grade` clamps at 0, so every repository worse than `normalized = 10`
reports the same `0.0` — and the tail is exactly what decides whether the
dampener works. The JSON report carries every finding, so the harness
re-derives the unclamped value using the same formula the product uses.

That means the harness holds a second copy of `finding_score`, over the JSON
shape instead of the dataclass. `tests/unit/test_calibration_harness.py`
enumerates every severity × confidence × category × top25 combination and
asserts the two agree, because a study that quietly measures a model the
product no longer uses is worse than no study: the bands chosen from it would
acquire an authority they never earned.

## Known bias in the corpus

These are all well-maintained open-source projects with their own security
processes. The distribution measured here is cleaner than the population this
tool will be pointed at. A median calibrated to earn a B here means *"as clean
as a well-run OSS project"*, not *"average code"*. That is a defensible target
and it is a choice — D5's to record, not the harness's to assume.

`maintainability-agent` has the same limitation; naming it is the difference
between a known bound and a surprise.
