# Scoring model

> Status: **v0.10.0 — 2026-09-11.** The scoring model, currently model 2.

> Letter-grade A+ → F, mapped from a 0.0 → 5.0 axis. Mirrors `maintainability-agent` so operators have one mental model for both gates.

## Inputs

For each unsuppressed canonical `Finding`:

| Input         | Source                                                                  |
|---------------|-------------------------------------------------------------------------|
| `severity`    | Scanner-emitted or override map (CRITICAL / HIGH / MEDIUM / LOW / INFO) |
| `confidence`  | Scanner-emitted (HIGH / MEDIUM / LOW)                                   |
| `category`    | Map from `canonical_cwe` (one of nine categories — see design.md §6)    |
| `cwe_top25`   | Boolean — does the CWE appear on the MITRE Top 25 (2025)?               |
| `suppressed`  | Boolean — has the operator acknowledged this finding in `.scignore.yaml`?|

Suppressed findings are excluded from scoring (they still appear in the report under "acknowledged").

## Weights

```python
SEVERITY_WEIGHT = {
    "critical":      10.0,
    "high":           4.0,
    "medium":         1.5,
    "low":            0.5,
    "informational":  0.0,
}

CONFIDENCE_WEIGHT = {
    "high":           1.00,
    "medium":         0.75,
    "low":            0.50,
}

CATEGORY_WEIGHT = {
    "secrets":               1.5,
    "code_vulnerabilities":  1.5,
    "auth_authz":            1.5,
    "crypto":                1.5,
    "dependencies":          1.0,
    "config_iac":            1.0,
    "supply_chain":          0.8,
    "logging_observability": 0.8,
    "policy_docs":           0.5,
}

CWE_TOP25_BONUS = 1.25  # multiplier when finding hits a Top-25 CWE
```

## Finding score

```python
finding_score = (
    SEVERITY_WEIGHT[severity]
    * CONFIDENCE_WEIGHT[confidence]
    * CATEGORY_WEIGHT[category]
    * (CWE_TOP25_BONUS if cwe_top25 else 1.0)
)
```

> **What `severity` is, and is not.** It is the scanner's answer to *"how
> confident am I that this pattern is present and matters in general"* — not
> *"how bad is this in your code"*. Bandit rates SQL injection **medium** and
> `hashlib.md5` **high**. It is a legitimate weight here and a legitimate
> filter in `fail_on_severity`, because both are honest uses of a confidence
> signal. It must not be used to *identify* the dangerous findings:
> [D15](decisions.md) records six candidate rules that tried, and the
> measurements showing none of them separate well-maintained code from a
> repository with planted vulnerabilities.

## Category subtotal

```python
category_subtotal = sum(finding_score for f in findings_in_category)
```

Each category's subtotal is normalized by **scanned code volume** so a 100k-LOC repo isn't penalized for naturally having more lines of code than a 1k-LOC one:

```python
category_normalized = category_subtotal / (loc_scanned / 1000)
```

This is a straight **density**: weighted findings per thousand lines of scanned code.

It was `sqrt(LOC/1000)` — borrowed from `maintainability-agent` — and that under-corrected, so the ranking followed how *big* a repository is rather than how much is wrong with it. Measured on the calibration corpus:

| repo | LOC | weighted findings / kLOC | `sqrt` normalized |
|---|---:|---:|---:|
| django | 144,473 | 1.51 | **18.18** ← ranked worst |
| flask | 7,841 | **3.35** | 9.38 |
| fastapi | 23,764 | 1.60 | 7.81 |

Flask carried 2.2× Django's density and normalized at half the value. Spearman correlation of grade against size was −0.37; of density against size, +0.12. The number was tracking the wrong variable. See [decisions.md](decisions.md) D16.

## Overall score

Map the worst category to a 0.0–5.0 axis. The **worst category drives the overall grade**, not an average — one CRITICAL secret in git history shouldn't be offset by a clean dependency tree.

```python
category_grade = clamp(5.0 - (category_normalized * 1.3), 0.0, 5.0)
overall_score  = min(category_grade for category in categories)
```

The slope moves with the normalizer, because the two only mean anything together. Slope cannot reorder anything, so it is chosen on where the median lands and how much of the corpus clamps at 0.0 and loses its tail. 1.3 is the largest slope that keeps well-maintained code medianing inside the B band while the two populations stay apart — see [decisions.md](decisions.md) D17.

### `secrets` is the exception

```python
secrets_normalized = secrets_subtotal / sqrt(loc_scanned / 1000)
```

One committed private key is one committed private key whether the repository is a thousand lines or a million. It is a count, not a rate.

This was found the hard way. OWASP Juice Shop — a training application written to be insecure — carries four hardcoded API keys and three private keys, and under straight density graded **B+**, because 115,340 lines of surrounding code divided seven committed credentials down to nothing. Flask, with no secrets at all, graded F.

`sqrt` rather than an absolute count, because a larger codebase genuinely does carry more configuration surface, and an absolute count failed Django on two low-confidence hits. Damped, not exempted.

## Letter grade

```python
def letter(score: float) -> str:
    if score >= 4.85: return "A+"
    if score >= 4.50: return "A"
    if score >= 4.00: return "A-"
    if score >= 3.50: return "B+"
    if score >= 3.00: return "B"
    if score >= 2.50: return "B-"
    if score >= 2.00: return "C"
    if score >= 1.00: return "D"
    return "F"
```

## Worked example

A repo with:

- 1 HIGH SQL-injection finding (`CWE-89`, high confidence, top-25, category `code_vulnerabilities`)
- 3 MEDIUM dependency CVEs (`CWE-1104`, medium confidence, not top-25, category `dependencies`)
- 0 of everything else

Scanned LOC: 12,000.

```text
SQLi:        4.0 (HIGH)  × 1.00 (HIGH conf)  × 1.5 (code_vulns)  × 1.25 (top25) = 7.50
Dep #1:      1.5 (MED)   × 0.75 (MED conf)   × 1.0 (deps)        × 1.00         = 1.13
Dep #2:      1.5 (MED)   × 0.75 (MED conf)   × 1.0 (deps)        × 1.00         = 1.13
Dep #3:      1.5 (MED)   × 0.75 (MED conf)   × 1.0 (deps)        × 1.00         = 1.13

code_vulnerabilities subtotal = 7.50
dependencies subtotal         = 3.39

Normalizer: 12000 / 1000 = 12.0   (secrets would use sqrt(12) = 3.46 — none here)

code_vulnerabilities normalized = 7.50 / 12.0 = 0.625 → grade = 5.0 - (0.625 × 1.3) = 4.19
dependencies normalized         = 3.39 / 12.0 = 0.283 → grade = 5.0 - (0.283 × 1.3) = 4.63

Overall = min(4.19, 4.63) = 4.19 → "A-"
```

**Read that last line carefully, because it is the honest cost of a density.** This repository has a live SQL injection and grades A−. One serious defect in twelve thousand lines *is* a low density, and the grade is reporting the density correctly.

The grade is therefore not the thing that catches it. Three other outputs are, and all of them fire here:

- The **work order** puts the SQLi in §FIX, first, with the file and line.
- `code_vulnerabilities` is named as the worst category in the report header.
- The default **`fail_on_new` gate** fails the build, because the finding is new.

A grade compresses a repository to one number so it can be compared against another repository and against itself last week. That is all it is for. If you are looking to the letter to tell you whether you have a vulnerability, look at the work order instead — [product intent](../README.md) puts it first class and the score second for exactly this reason.

## Configurable hard gates

The score itself is informational — the **gates** are what fail CI. Default gates (override via config):

```json
"gates": {
  "fail_on_severity":    ["critical", "high"],
  "fail_on_category":    ["secrets", "auth_authz"],
  "fail_on_new":         true,
  "min_score":           4.0,
  "max_unsuppressed":    { "high": 0, "medium": 10 }
}
```

Gates compose with OR semantics. Any tripped gate = nonzero exit.

## Why a single worst-category drives the grade

Two designs were considered:

1. **Average across categories** — easy to game (one perfect category masks a wholly broken one).
2. **Min across categories (chosen)** — hard to game; an operator who wants A+ must fix every category. Mirrors `maintainability-agent`'s pattern.

A future config option will allow `score_mode: "average"` for teams who prefer it, but **`min` is the default** because security gates should reward thoroughness, not pretty averages.

## Drift testing

`tests/unit/test_scoring.py` locks the scoring arithmetic and gate semantics.

Since 2026-09-09 the repository also ships
`tests/integration/test_scoring_drift.py`, the drift suite `CONTRIBUTING.md`
had cited for far longer than it existed. It pins the letter bands and the
properties that must survive any retuning: severity ordering is monotonic,
informational findings never move the grade, the overall grade is the worst
category rather than the mean, suppressed findings do not count, more findings
never improve the score, and a perfect score sits beside failed coverage
without either deriving from the other.

**It proves the scale is stable. D17 is what establishes it is correct** —
to the extent anything can. The corpus now carries both populations, and the
scale orders them perfectly: AUC 1.00, separation +1.26, every
vulnerable-by-design application at F and well-maintained code medianing at
3.41 (B).

What that does **not** establish is the edges between adjacent letters above
D/F. A−, B and C contain no corpus observation at all, and no larger corpus
fixes that: at the top of the scale the difference between two repositories is
five findings versus eight in twenty thousand lines, and nothing says one of
those deserves A and the other A+. Treat those edges as presentational
granularity. A B+ is not meaningfully better than an A−. Changes in scanner
output distributions still require release review.
