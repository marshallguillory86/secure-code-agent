# Scoring model

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
category_normalized = category_subtotal / sqrt(loc_scanned / 1000)
```

`sqrt(LOC/1000)` is the same dampener `maintainability-agent` uses. It sub-linearly penalizes scale — a 10× larger codebase only suffers a ~3.16× normalization, not 10×.

## Overall score

Map the worst category to a 0.0–5.0 axis. The **worst category drives the overall grade**, not an average — one CRITICAL secret in git history shouldn't be offset by a clean dependency tree.

```python
category_grade = clamp(5.0 - (category_normalized * 0.5), 0.0, 5.0)
overall_score  = min(category_grade for category in categories)
```

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

Normalizer: sqrt(12000 / 1000) = sqrt(12) = 3.46

code_vulnerabilities normalized = 7.50 / 3.46 = 2.17 → grade = 5.0 - (2.17 × 0.5) = 3.92
dependencies normalized         = 3.39 / 3.46 = 0.98 → grade = 5.0 - (0.98 × 0.5) = 4.51

Overall = min(3.92, 4.51) = 3.92 → "B+"
```

The SQLi finding alone dropped the repo to B+; the operator sees `code_vulnerabilities` as the worst-performing bucket in the report header and knows where to look.

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

**It proves the scale is stable, not that it is correct.** Nobody has
established that A+ corresponds to anything real — that is D5, still open —
and pinning an uncalibrated number does not calibrate it. Changes in scanner
output distributions still require release review.
