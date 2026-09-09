# Calibration study — 2026-09-09

The study [D5](decisions.md) has owed since 2026-09-08. The letter bands were
borrowed from `maintainability-agent` without its calibration study, and the
`sqrt(LOC/1000)` dampener is an invented normalizer with no corpus behind it.

Method, corpus and harness: [`calibration/`](../calibration/README.md).
Raw data: [`calibration/results.json`](../calibration/results.json).

## Result in one line

**The bands are approximately right; the inputs are wrong, and there is more
than one of them.** Separating the test tree from the primary tree — the single
biggest input error — cuts the corpus median distortion by seventy percent. It
is not enough on its own. Dependency findings are the next lever, and after
both the median still sits below the bottom of the scale.

## A correction to an earlier version of this study

The first pass of this analysis filtered test findings out of the numerator
while still dividing by the **whole tree's** LOC. Every "excluding tests"
figure it produced was therefore too generous — it reported a median of 4.36
and a corrected grade of B, and both were wrong.

That is the same numerator/denominator mismatch `paths.exclude_patterns` caused
before it was fixed, arriving by a different door and in the tool built to
measure it. The split is now done inside the product, where `loc_under()`
returns primary and test counts together and the denominator cannot drift from
the numerator. The numbers below are the product's own.

## What was measured

Fourteen repositories pinned by commit, spanning Python, JavaScript, Go, Ruby
and Java. Each audited through the real CLI with one shared config and a fixed
ten-scanner set, with the primary tree scored and the test tree reported
separately.

| repo | lang | primary LOC | findings | test LOC | test findings | score |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| django | python | 145,456 | 364 | 319,577 | 987 | 0.00 **F** |
| flask | python | 8,284 | 80 | 6,077 | 1071 | 0.00 **F** |
| requests | python | 5,965 | 23 | 4,284 | 692 | 0.00 **F** |
| httpx | python | 7,585 | 85 | 16,674 | 1304 | 0.00 **F** |
| fastapi | python | 35,655 | 257 | 69,283 | 4896 | 0.00 **F** |
| lodash | javascript | 25,944 | 159 | 22,198 | 0 | 0.00 **F** |
| gin | go | 16,823 | 14 | 4,032 | 0 | 0.00 **F** |
| sinatra | ruby | 7,135 | 13 | 13,759 | 5 | 0.00 **F** |
| axios | javascript | 26,788 | 21 | 28,423 | 45 | 1.69 D |
| jekyll | ruby | 14,590 | 10 | 8,900 | 0 | 2.55 B− |
| commons-lang | java | 97,561 | 7 | 92,783 | 0 | 4.15 A− |
| logrus | go | 6,609 | 4 | 1,155 | 0 | 4.64 A |
| express | javascript | 4,497 | 3 | 13,483 | 90 | 5.00 A+ |
| gson | java | 21,784 | 4 | 29,087 | 0 | 5.00 A+ |

Note the test trees. Django's is **larger than its primary tree** — 319,577
lines against 145,456 — and `gson`, `express` and `sinatra` all have more test
code than source. Before the split, all of that sat in the denominator making
scores look better while its findings made them worse. Now both move together.

## What the split was worth, and what it was not

| | median `worst_normalized` | median grade |
| --- | ---: | --- |
| before the split (whole tree scored) | 50.15 | 0.00 **F** |
| **after the split** (primary tree scored) | **15.36** | 0.00 **F** |
| after the split, dependencies also excluded | 7.32 | 1.34 **D** |
| dropping LOW severity instead | 15.36 | 0.00 **F** |

Separating the test tree removes about seventy percent of the distortion, and
median unclamped score improves from **−20.08 to −2.68**. Eight repositories
still score F rather than ten. Dropping LOW severity now changes *nothing* at
the median, because the low-severity noise was overwhelmingly in the test tree
and has already been moved out of the score.

**It is still not a usable scale.** The median repository remains past the
floor, and the ordering still tracks scanner verbosity: every Python project is
F, while Java and Go sit at A− to A+.

## What remains, measured

**Dependency findings are now the largest single lever** — median 15.36 → 7.32.
For `lodash`, 154 of 159 findings are CVEs in `package-lock.json`. For `httpx`,
54 of 85. These are true positives; the question is whether a library's
dev-dependency CVEs should sink its *code* security grade, or belong on their
own axis the way the test tree now does.

**Bandit's low-confidence output on primary source is the rest.** With tests
excluded, Django still carries 107 `B703`/`B308` findings — `mark_safe`, which
is Django's own template-escaping API, flagged in the framework that defines
it. FastAPI carries 107 `B101` asserts in non-test source.

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

D5 stays **open**, and one of its two input questions is now answered in code.

**Answered — test directories.** They are separated rather than excluded: the
primary tree is scored, the test tree is reported beside it, and `secrets`
findings stay in the score wherever they live, because a committed credential
is a leak whatever directory it sits in. The corpus supports the exemption
directly: every `secrets` finding inside a test tree came from gitleaks, and
none from Bandit's hardcoded-password heuristics. Configurable via
`paths.test_patterns`.

**Still open — dependency findings.** Worth a median of 15.36 → 7.32. Whether a
library's dev-dependency CVEs should sink its code-security grade, or sit on
their own axis the way the test tree now does, is the same shape of question
and has the same shape of answer available.

**Still open — band edges.** They cannot be chosen while the median sits past
the floor. Choosing them now would be fitting numbers to noise, which is what
D5 was raised to prevent.
