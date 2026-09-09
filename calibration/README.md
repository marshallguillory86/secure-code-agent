# Calibration

The method [D5](../docs/decisions.md) owes. `docs/decisions.md` has carried
*"Open — method needed"* since 2026-09-08: the letter bands were borrowed from
`maintainability-agent` without its calibration study, and the
`sqrt(LOC/1000)` dampener is an invented normalizer with no corpus behind it.

```
python calibration/calibrate.py                       # whole corpus
python calibration/calibrate.py --only flask,gin      # one or two
```

Results land in `results.json`; the study itself is
[`docs/calibration.md`](../docs/calibration.md).

## The three files

**`corpus.json`** — fourteen repositories pinned by commit. Selected to span
the languages the floor actually reads, and roughly two orders of magnitude of
size, because a corpus of similarly-sized repositories cannot tell us anything
about a size normalizer.

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

## Three choices that move the result

Stated here so they can be argued with, rather than discovered in the numbers.

1. **Test directories are included.** The tool's own `DEFAULT_EXCLUDES` do not
   exclude them, and a calibration should measure what the tool does by
   default. Test trees carry deliberately-odd code, so this biases the corpus
   slightly worse than production-only would. Excluding them is defensible and
   would need a re-run, not an adjustment.
2. **`vendor/` and `target/` are excluded** on top of the defaults. Both hold
   third-party or generated code — Go vendoring, Maven output — and scoring a
   project on its dependencies' source measures the wrong thing. This is the
   only deviation from `DEFAULT_EXCLUDES`.
3. **Scorecard and gosec are not in the scanner set.** Scorecard is
   repository-cadence and needs a GitHub token; gosec needs each project's own
   Go toolchain ([D12](../docs/decisions.md)). Including a tool that runs for
   some repositories and not others would put the difference into the
   distribution.

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
