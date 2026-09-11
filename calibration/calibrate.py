#!/usr/bin/env python3
"""Measure the score distribution over a pinned corpus. The method D5 owes.

`docs/decisions.md` D5 read "Open — method needed" from 2026-09-08 until D16
and D17 closed it on 2026-09-11. The
letter bands were borrowed from `maintainability-agent` without its calibration
study, and the dampener was an invented normalizer with no corpus behind it.
Nobody had established that A+ meant anything. D16 settled the normalizer from
this corpus; the bands themselves are still borrowed.

This is the harness, not the answer. It audits every repository in
`corpus.json` at its pinned commit with a fixed scanner set, and reports the
distribution of what the scoring model produces. Bands are then chosen *from*
that distribution rather than asserted ahead of it — which is the whole
difference between a calibrated scale and a set of numbers someone liked.

**Subtotals are recomputed from the findings, not read off the grades.**
`category_grade` clamps at 0, so every repository worse than `normalized = 10`
reports the same 0.0 and the tail — the part that decides whether the dampener
works — is exactly what gets destroyed. The JSON report carries every finding,
so the harness re-derives the unclamped value with the same `finding_score`
the product uses.

Usage:
    python calibration/calibrate.py --out calibration/results.json
    python calibration/calibrate.py --out results.json --only django,flask

It clones into a work directory, shallow-fetching each pinned commit, and
leaves the clones in place so a re-run is cheap. Nothing here is imported by
the package; it is a study tool that happens to live in the repository so the
study can be reproduced.
"""

from __future__ import annotations

import argparse
import json
import math
import statistics
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from secure_code_audit.findings import (  # noqa: E402
    Category,
    Confidence,
    Severity,
)
from secure_code_audit.scoring import (  # noqa: E402
    CATEGORY_WEIGHT,
    CONFIDENCE_WEIGHT,
    CWE_TOP25_BONUS,
    GRADE_SLOPE,
    SEVERITY_WEIGHT,
    letter_grade,
    normalize,
)

#: Scanners the study runs. Fixed deliberately: a distribution measured with a
#: different tool set on different repositories is not a distribution. Scorecard
#: is excluded because it is repository-cadence and needs a GitHub token;
#: gosec because it needs each project's own Go toolchain (D12).
SCANNER_SET = (
    "builtin_rules,bandit,semgrep,njsscan,rubocop,pip_audit,osv_scanner,gitleaks,checkov,trivy"
)


def _run(args: list[str], cwd: Path | None = None, timeout: int = 1800):
    return subprocess.run(
        args,
        cwd=str(cwd) if cwd else None,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def fetch(entry: dict, work: Path) -> Path:
    """Shallow-fetch one pinned commit. Idempotent across runs."""
    target = work / entry["name"]
    if (target / ".git").exists():
        head = _run(["git", "rev-parse", "HEAD"], cwd=target).stdout.strip()
        if head == entry["commit"]:
            return target
    target.mkdir(parents=True, exist_ok=True)
    _run(["git", "init", "-q"], cwd=target)
    _run(["git", "remote", "remove", "origin"], cwd=target)
    _run(["git", "remote", "add", "origin", entry["url"]], cwd=target)
    # Fetching the SHA directly keeps the clone shallow *and* exactly pinned.
    result = _run(["git", "fetch", "--depth", "1", "-q", "origin", entry["commit"]], cwd=target)
    if result.returncode != 0:
        raise RuntimeError(f"{entry['name']}: fetch failed: {result.stderr[:300]}")
    _run(["git", "checkout", "-q", "FETCH_HEAD"], cwd=target)
    return target


def audit(target: Path, report: Path, config: Path) -> dict:
    """Run the real CLI, so the study measures the product and not a copy.

    `--config` is mandatory here. Without it the audit loads the *audited
    project's* own secure-code-agent.json when it has one, and a corpus where
    two repositories were measured under different exclude_patterns is not a
    distribution — it is a collection of unrelated numbers.
    """
    # A report left by an earlier run must not be able to stand in for this
    # one. Checking only that the file *exists* let a failed audit read as a
    # clean result: on the first corpus pass the CLI rejected the config for
    # every repository, and the one with a stale report on disk reported a
    # score anyway. That is the same absence-of-evidence failure the gosec
    # adapter exists to prevent, reproduced in the harness that measures it.
    report.unlink(missing_ok=True)
    result = _run(
        [
            sys.executable,
            "-m",
            "secure_code_audit.cli",
            str(target),
            "--config",
            str(config),
            "--only-scanners",
            SCANNER_SET,
            "--json-output",
            str(report),
        ],
        timeout=3600,
    )
    if not report.exists():
        raise RuntimeError(
            f"no report produced (exit {result.returncode}): "
            f"{(result.stderr or result.stdout)[-400:]}"
        )
    return json.loads(report.read_text(encoding="utf-8"))


def _finding_score(finding: dict) -> float:
    """`scoring.finding_score`, over the JSON shape rather than the dataclass."""
    if finding.get("suppressed"):
        return 0.0
    severity = Severity.from_string(finding["severity"])
    confidence = Confidence.from_string(finding["confidence"])
    category = Category(finding["category"])
    base = SEVERITY_WEIGHT[severity] * CONFIDENCE_WEIGHT[confidence] * CATEGORY_WEIGHT[category]
    if finding.get("cwe_top25"):
        base *= CWE_TOP25_BONUS
    return base


def _subtotals(findings: list[dict]) -> dict[str, float]:
    """`scoring.category_subtotal` for every category at once, over JSON.

    **This must stay in step with the product, and twice it has not been.**
    The harness used to sum each category flat, which was correct until the
    product started saturating repeats of one rule at `weight / sqrt(k)`;
    after that the study's subtotal for Django read 488.06 against the
    product's 218.5 and nothing complained. It also carried its own
    `sqrt(LOC/1000)` divisor and its own `0.5` slope, both of which the
    product has since changed.

    The divisor and the slope are now imported rather than copied. The rank
    discount cannot be imported — `category_subtotal` takes `Finding`
    objects and a saved report holds dicts — so it is reimplemented here and
    `tests/unit/test_calibration_harness.py` pins the two against each other.
    """
    by_rule: dict[tuple[str, str], list[float]] = {}
    for finding in findings:
        key = (finding["category"], finding["rule_id"])
        by_rule.setdefault(key, []).append(_finding_score(finding))

    subtotals: dict[str, float] = {c.value: 0.0 for c in Category}
    for (category, _rule), scores in by_rule.items():
        subtotals[category] += sum(
            score / math.sqrt(rank) for rank, score in enumerate(sorted(scores, reverse=True), 1)
        )
    return subtotals


def scored_findings(payload: dict) -> list[dict]:
    """Only what the score actually counted.

    `findings` is the complete list and carries an `axis` tag; anything not on
    the primary axis was reported beside the score, not in it. An earlier
    version of this harness summed the whole array and so reported a median
    over dependency findings the product does not score.
    """
    return [f for f in payload["findings"] if f.get("axis", "primary") == "primary"]


def measure(payload: dict) -> dict:
    """Per-category subtotals and *unclamped* normalized values."""
    loc = int(payload["score"]["loc_scanned"])
    subtotals = _subtotals(scored_findings(payload))

    normalized = {name: normalize(value, loc, name) for name, value in subtotals.items()}
    # The product clamps this to [0, 5]; the study keeps the raw value so the
    # tail survives. `unclamped_overall` can go negative, and that is the point.
    unclamped = {name: 5.0 - (value * GRADE_SLOPE) for name, value in normalized.items()}
    worst = min(unclamped.values()) if unclamped else 5.0

    return {
        "loc_scanned": loc,
        "subtotals": {k: round(v, 3) for k, v in subtotals.items() if v},
        "normalized": {k: round(v, 4) for k, v in normalized.items() if v},
        "worst_normalized": round(max(normalized.values()) if normalized else 0.0, 4),
        "unclamped_overall": round(worst, 4),
        "reported_overall": payload["score"]["overall"],
        "reported_letter": payload["score"]["letter"],
        "worst_category": payload["score"]["worst_category"],
        "finding_count": len(scored_findings(payload)),
        "reported_count": len(payload["findings"]),
        "per_severity": payload["score"]["per_severity_count"],
        "coverage_status": (payload.get("coverage") or {}).get("status"),
    }


#: The input question the study still has to answer. Test directories are no
#: longer one of them: the product now partitions them natively, so "as-run"
#: already means "primary tree, primary LOC".
#:
#: An earlier version of this analysis filtered test findings out of the
#: numerator while still dividing by the *whole* tree's LOC, which made every
#: "no-tests" figure too generous — the same numerator/denominator mismatch
#: `exclude_patterns` caused once already. Doing the split in the product
#: rather than in the analysis is what makes that mistake unavailable.
VARIANTS: dict[str, object] = {
    "as-run": lambda f: True,
    "no-deps": lambda f: f["category"] != "dependencies",
    "no-low": lambda f: f["severity"] != "low",
}


def worst_normalized(findings: list[dict], loc: int) -> float:
    return max(
        (normalize(value, loc, name) for name, value in _subtotals(findings).items()),
        default=0.0,
    )


def variants(reports: Path) -> dict:
    """Re-analyze saved reports under each remaining input rule.

    No re-scanning: every finding is already in the report, so the expensive
    part is done once and the variants cannot disagree because of a re-scan
    drifting underneath them. `loc_scanned` is the primary-tree count, so the
    denominator matches the numerator in every variant.
    """
    rows: dict[str, dict[str, float]] = {}
    for path in sorted(reports.glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        loc = int(payload["score"]["loc_scanned"])
        scored = scored_findings(payload)
        rows[path.stem] = {
            name: round(worst_normalized([f for f in scored if keep(f)], loc), 4)
            for name, keep in VARIANTS.items()
        }
        # The side axes moved under `reported_not_scored` when the test tree
        # stopped being the only one. Reading the old top-level key did not
        # fail — it defaulted to zero, so the study reported that no corpus
        # repository had a test tree while the product was correctly setting
        # 983 test findings aside for Django alone.
        tree = payload["reported_not_scored"]["test_tree"]
        rows[path.stem]["test_tree_findings"] = float(tree["count"])
        rows[path.stem]["test_tree_loc"] = float(tree["loc"] or 0)
    medians = {
        name: round(statistics.median([r[name] for r in rows.values()]), 4)
        for name in VARIANTS
        if rows
    }
    return {
        "per_repository": rows,
        "median_worst_normalized": medians,
        "median_grade_at_current_slope": {
            name: round(max(0.0, 5.0 - value * GRADE_SLOPE), 2) for name, value in medians.items()
        },
    }


def percentiles(values: list[float]) -> dict[str, float]:
    if not values:
        return {}
    ordered = sorted(values)

    def at(fraction: float) -> float:
        index = min(len(ordered) - 1, max(0, round(fraction * (len(ordered) - 1))))
        return round(ordered[index], 4)

    return {
        "min": round(ordered[0], 4),
        "p25": at(0.25),
        "median": round(statistics.median(ordered), 4),
        "p75": at(0.75),
        "max": round(ordered[-1], 4),
    }


#: A scanner that actually reads each language. Without one of these having
#: completed, a repository of that language was not examined — it was
#: glanced at by gitleaks and a twenty-rule offline Semgrep profile.
LANGUAGE_SCANNERS: dict[str, tuple[str, ...]] = {
    "python": ("bandit",),
    "javascript": ("njsscan",),
    "typescript": ("njsscan",),
    "ruby": ("rubocop",),
    "go": ("gosec",),
    "java": (),  # D12: PMD covers none of it, SpotBugs needs compiled bytecode.
}


def examined(row: dict) -> bool:
    """Did a scanner that reads this repository's language actually run?

    The product refuses to grade what it did not examine (P7). A study that
    computes a median over repositories in the same position is doing the
    thing the product refuses to do, and the numbers say why: Python
    repositories in this corpus produce 712 to 5,107 real findings each,
    while Go, Java and — before njsscan and RuboCop were installed —
    JavaScript and Ruby produce nought to four. Three orders of magnitude.
    That gap is the floor's language coverage, not those projects being
    thirty times cleaner than Django.

    Including them drags any percentile toward "clean" and makes band edges
    chosen from it meaningless. So they are measured, reported, and kept out
    of the distribution, exactly as the product keeps an ungraded run out of
    a trend.
    """
    language = (row.get("language") or "").lower()
    required = LANGUAGE_SCANNERS.get(language)
    if not required:
        # No scanner in the floor reads this language at all (D12: Java).
        return False
    completed = {
        s["name"]
        for s in (row.get("coverage") or {}).get("scanners", [])
        if s.get("outcome") == "completed"
    }
    return any(name in completed for name in required)


def summarize(rows: list[dict]) -> dict:
    """Three distributions, because one of them cannot answer the question.

    `examined_overall` is every repository a scanner could read, and it is
    what the *centre* of the scale is calibrated against. It cannot set the
    band edges, because the maintained half has no bad end — the corpus
    comment said so from the first version: "the distribution measured here
    is cleaner than the population this tool will actually be pointed at."

    So the two populations are reported apart. `maintained_overall` is where
    well-run OSS lands; `vulnerable_overall` is where applications written to
    be vulnerable land. A band table is defensible exactly to the extent that
    those two do not overlap, and D17 records the separation measured here.
    """
    ok = [r for r in rows if "error" not in r]
    seen = [r for r in ok if r.get("examined")]
    unexamined = [r["name"] for r in ok if not r.get("examined")]

    def by_kind(kind: str) -> list[dict]:
        return [r for r in seen if (r.get("kind") or "maintained") == kind]

    maintained = by_kind("maintained")
    vulnerable = by_kind("vulnerable-by-design")

    def grades(subset: list[dict]) -> list[float]:
        return [r["measure"]["reported_overall"] for r in subset]

    return {
        # The two populations, kept apart. Pooling them would produce a
        # median describing neither.
        "maintained": len(maintained),
        "maintained_overall": percentiles(grades(maintained)) if maintained else None,
        "maintained_letters": sorted(
            (r["name"], r["measure"]["reported_letter"]) for r in maintained
        ),
        "vulnerable": len(vulnerable),
        "vulnerable_overall": percentiles(grades(vulnerable)) if vulnerable else None,
        "vulnerable_letters": sorted(
            (r["name"], r["measure"]["reported_letter"]) for r in vulnerable
        ),
        # The gap between the worst maintained repository and the best
        # vulnerable-by-design one. Negative means the populations overlap
        # and no band edge between them can separate them.
        "separation": (
            round(min(grades(maintained)) - max(grades(vulnerable)), 4)
            if maintained and vulnerable
            else None
        ),
        "repositories": len(rows),
        "measured": len(ok),
        "failed": [r["name"] for r in rows if "error" in r],
        # The band-edge distribution, over repositories a language scanner
        # actually read. This is the one to calibrate from.
        "examined": len(seen),
        "unexamined": unexamined,
        "examined_overall": percentiles([r["measure"]["reported_overall"] for r in seen])
        if seen
        else None,
        "examined_worst_normalized": percentiles([r["measure"]["worst_normalized"] for r in seen])
        if seen
        else None,
        "reported_overall": percentiles([r["measure"]["reported_overall"] for r in ok]),
        "unclamped_overall": percentiles([r["measure"]["unclamped_overall"] for r in ok]),
        "worst_normalized": percentiles([r["measure"]["worst_normalized"] for r in ok]),
        "loc": percentiles([float(r["measure"]["loc_scanned"]) for r in ok]),
        "letters": {
            letter: sum(1 for r in ok if r["measure"]["reported_letter"] == letter)
            for letter in sorted({r["measure"]["reported_letter"] for r in ok})
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", default=str(Path(__file__).parent / "corpus.json"))
    parser.add_argument("--work", default=str(Path(__file__).parent / ".corpus"))
    parser.add_argument("--out", default=str(Path(__file__).parent / "results.json"))
    parser.add_argument("--only", default="", help="Comma-separated repository names.")
    parser.add_argument(
        "--config",
        default=str(Path(__file__).parent / "calibration-config.json"),
        help="One config for every repository. See calibration-config.json.",
    )
    args = parser.parse_args()

    corpus = json.loads(Path(args.corpus).read_text(encoding="utf-8"))
    entries = corpus["repositories"]
    if args.only:
        wanted = {name.strip() for name in args.only.split(",")}
        entries = [e for e in entries if e["name"] in wanted]

    work = Path(args.work)
    work.mkdir(parents=True, exist_ok=True)
    reports = work / "_reports"
    reports.mkdir(exist_ok=True)

    rows: list[dict] = []
    for index, entry in enumerate(entries, start=1):
        name = entry["name"]
        print(f"[{index}/{len(entries)}] {name} … ", end="", flush=True)
        started = time.time()
        row: dict = {"name": name, "commit": entry["commit"], "language": entry["language"]}
        row["kind"] = entry.get("kind", "maintained")
        try:
            target = fetch(entry, work)
            payload = audit(target, reports / f"{name}.json", Path(args.config))
            row["measure"] = measure(payload)
            row["coverage"] = payload.get("coverage") or {}
            row["examined"] = examined(row)
            print(
                f"{row['measure']['reported_overall']:.2f} "
                f"({row['measure']['reported_letter']})  "
                f"loc={row['measure']['loc_scanned']:,}  "
                f"findings={row['measure']['finding_count']}  "
                f"{'' if row['examined'] else 'UNEXAMINED  '}"
                f"{time.time() - started:.0f}s"
            )
        except Exception as exc:  # noqa: BLE001 — a study run must not die on one repo
            row["error"] = f"{type(exc).__name__}: {exc}"
            print(f"FAILED — {row['error'][:120]}")
        rows.append(row)

    summary = summarize(rows)
    summary["variants"] = variants(reports)
    Path(args.out).write_text(
        json.dumps(
            {
                "corpus": args.corpus,
                "config": args.config,
                "scanner_set": SCANNER_SET,
                "summary": summary,
                "rows": rows,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    print("\n--- distribution ---")
    print(json.dumps(summary, indent=2))
    # The *examined* median, not the median over all 14. Six repositories in
    # this corpus have no scanner that can read their language, so they report
    # zero findings and grade A+ — and including them pulled the headline
    # median to 4.09 (A-) while the repositories anything actually looked at
    # sat at 3.20 (B). Reporting the first as "the distribution" is P7 broken
    # in the study that exists to check the scale.
    # The *maintained* median, not the pooled one. Once the corpus grew a
    # vulnerable-by-design half, a median over both described neither
    # population — it just moved with however many training applications
    # happened to be in the list.
    maintained = summary.get("maintained_overall") or {}
    vulnerable = summary.get("vulnerable_overall") or {}
    median = maintained.get("median")
    if median is None:
        print(
            "\nNo maintained repository in this corpus was examined by a scanner "
            "that reads its language, so there is no distribution to calibrate from."
        )
        return 0

    print(
        f"\nMaintained median: {median} → {letter_grade(max(0.0, min(5.0, median)))} "
        f"across {summary['maintained']} repositories. "
        f"The calibration target (D5) is the B band [3.00, 3.50)."
    )
    if vulnerable:
        print(
            f"Vulnerable-by-design median: {vulnerable.get('median')} → "
            f"{letter_grade(max(0.0, min(5.0, vulnerable.get('median', 0.0))))} "
            f"across {summary['vulnerable']} repositories."
        )
    separation = summary.get("separation")
    if separation is not None:
        verdict = (
            "the populations do not overlap, so a band edge can separate them"
            if separation > 0
            else "THE POPULATIONS OVERLAP — no band table can separate them"
        )
        print(f"Separation: {separation:+.2f} — {verdict}.")
    unexamined = summary["measured"] - summary["examined"]
    if unexamined:
        print(
            f"{unexamined} of {summary['measured']} repositories were not examined "
            f"and are excluded from every figure above."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
