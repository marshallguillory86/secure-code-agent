"""The two figures the decision register cites, and the run that produces them.

`tests/unit/test_calibration_harness.py` pins the harness's *scoring* against
the product's. This file covers the two declarations nothing covered at all:
`summarize`, which builds the distribution D16 and D17 were settled from, and
`main`, which drives the corpus loop and writes `calibration/results.json`.

Why these two in particular:

- **The populations must stay apart.** `docs/decisions.md` D17 records a
  *separation*: the worst maintained repository minus the best
  vulnerable-by-design one. Pool the two halves and the median describes
  neither population — it just moves with however many training applications
  happen to be in `corpus.json`. Nothing checked that the split was real.
- **Unexamined is not clean.** WebGoat is in the corpus specifically to grade
  A+ while being deliberately vulnerable, because no offline SAST in the floor
  reads Java (D12). If an unexamined repository ever reached a percentile, the
  band edges would be chosen partly from repositories nobody looked at.
- **Silence beats a fabricated number.** With nothing examined there is no
  distribution, and the harness has to say so rather than report a zero.

`fetch` and `audit` are substituted in the `main` tests: the real ones clone
over the network and shell out to the CLI. Everything between them — argument
handling, the corpus loop, the error path, the results file and the printed
summary — is driven for real.

**The file name is deliberate.** The rest of this suite is named for
behaviour, which the maintainability audit reads through imports: a test file
that imports a module counts as its pair. `calibration/calibrate.py` is not
importable as a package, so both of its test files load it by path and neither
has an import statement naming it — which is why a module with a test file
beside it was still reported as unpaired production code, with `summarize` and
`main` as its two fail-band declarations. The conventional name is the only
pairing evidence a path-loaded module can carry.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent.parent
HARNESS = REPO / "calibration" / "calibrate.py"


def _harness():
    spec = importlib.util.spec_from_file_location("calibrate", HARNESS)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# summarize
# ---------------------------------------------------------------------------


def _row(
    harness,
    name: str,
    *,
    overall: float,
    kind: str | None = "maintained",
    language: str = "python",
    letter: str = "B",
    worst_normalized: float = 1.0,
    loc: int = 10_000,
) -> dict:
    """One measured corpus row, with `examined` decided by the harness itself.

    `language="java"` is how a row becomes unexamined, because that is how it
    happens in the real corpus: the scanners ran, and none of them reads the
    language (D12).
    """
    row = {
        "name": name,
        "language": language,
        "coverage": {
            "scanners": [
                {"name": "bandit", "outcome": "completed"},
                {"name": "gitleaks", "outcome": "completed"},
            ]
        },
        "measure": {
            "reported_overall": overall,
            "reported_letter": letter,
            "worst_normalized": worst_normalized,
            "unclamped_overall": overall,
            "loc_scanned": loc,
        },
    }
    if kind is not None:
        row["kind"] = kind
    row["examined"] = harness.examined(row)
    return row


def test_the_two_populations_are_reported_separately_and_never_pooled():
    """A median over both halves describes neither.

    The corpus grew a vulnerable-by-design half precisely so the bad end of
    the scale had evidence behind it. Summing the halves into one distribution
    would undo that: the headline would then move with the ratio of training
    applications to real projects, which is a property of the list and not of
    the scoring model.
    """
    harness = _harness()
    rows = [
        _row(harness, "django", overall=3.5),
        _row(harness, "flask", overall=4.5),
        _row(harness, "pygoat", overall=0.0, kind="vulnerable-by-design"),
        _row(harness, "nodegoat", overall=0.5, kind="vulnerable-by-design"),
    ]

    summary = harness.summarize(rows)

    assert summary["maintained"] == 2
    assert summary["vulnerable"] == 2
    # Each population's own min, median and max — not the pooled 2.0.
    assert summary["maintained_overall"] == {
        "min": 3.5,
        "p25": 3.5,
        "median": 4.0,
        "p75": 4.5,
        "max": 4.5,
    }
    assert summary["vulnerable_overall"] == {
        "min": 0.0,
        "p25": 0.0,
        "median": 0.25,
        "p75": 0.5,
        "max": 0.5,
    }
    pooled = harness.percentiles([3.5, 4.5, 0.0, 0.5])["median"]
    assert pooled == 2.0
    assert summary["maintained_overall"]["median"] != pooled
    assert summary["vulnerable_overall"]["median"] != pooled


def test_separation_is_the_worst_maintained_minus_the_best_vulnerable():
    """D17's figure, with the arithmetic pinned.

    The numbers below are chosen so that no other plausible reading agrees:
    the difference of medians is 3.125, of means 2.625, of the extremes 4.0.
    Only `min(maintained) - max(vulnerable)` is 0.75.
    """
    harness = _harness()
    rows = [
        _row(harness, "a", overall=2.0),
        _row(harness, "b", overall=4.0),
        _row(harness, "c", overall=4.5),
        _row(harness, "goat-1", overall=0.5, kind="vulnerable-by-design"),
        _row(harness, "goat-2", overall=1.25, kind="vulnerable-by-design"),
    ]

    summary = harness.summarize(rows)

    assert summary["separation"] == pytest.approx(0.75), (
        "separation is not the worst maintained grade minus the best "
        "vulnerable one; a median, mean or extremes reading would give "
        "3.125, 2.625 or 4.0"
    )


def test_separation_goes_negative_when_the_populations_overlap():
    """A positive separation is the licence to place a band edge between the
    halves. An overlap must therefore be reported as a signed number that can
    be below zero, not clamped, floored or reported as absent."""
    harness = _harness()
    rows = [
        _row(harness, "a", overall=1.0),
        _row(harness, "b", overall=3.0),
        _row(harness, "goat-1", overall=0.25, kind="vulnerable-by-design"),
        _row(harness, "goat-2", overall=2.5, kind="vulnerable-by-design"),
    ]

    summary = harness.summarize(rows)

    assert summary["separation"] == pytest.approx(-1.5)
    assert summary["separation"] < 0


def test_separation_is_absent_rather_than_zero_when_one_half_is_missing():
    """Zero would read as "the two populations touch exactly", which is a
    measurement. With no vulnerable half there is no measurement, and a
    `--only` run over maintained repositories is exactly how that happens."""
    harness = _harness()
    rows = [_row(harness, "django", overall=3.5), _row(harness, "flask", overall=4.5)]

    summary = harness.summarize(rows)

    assert summary["separation"] is None
    assert summary["vulnerable"] == 0
    assert summary["vulnerable_overall"] is None
    # The half that *was* measured is still reported.
    assert summary["maintained_overall"]["median"] == 4.0


def test_a_row_without_a_kind_counts_as_maintained():
    """`corpus.json` carried no `kind` before the vulnerable half existed, and
    `calibrate.py` still defaults to maintained. If that default ever flipped,
    an unlabelled entry would land in the vulnerable population and drag the
    bad end of the scale toward clean."""
    harness = _harness()
    rows = [_row(harness, "django", overall=3.5, kind=None)]

    summary = harness.summarize(rows)

    assert summary["maintained"] == 1
    assert summary["vulnerable"] == 0
    assert summary["maintained_overall"]["median"] == 3.5


def test_a_vulnerable_repository_nobody_could_read_is_excluded_and_named():
    """WebGoat is the sharpest case in the corpus.

    It is deliberately vulnerable Java, and no offline scanner in the floor
    reads Java (D12), so it grades A+. Letting it into `vulnerable_overall`
    would put the bad end of the scale at 5.0 and make the separation figure
    report an overlap that does not exist. It must be named instead.
    """
    harness = _harness()
    rows = [
        _row(harness, "django", overall=3.5),
        _row(harness, "webgoat", overall=5.0, kind="vulnerable-by-design", language="java"),
    ]

    summary = harness.summarize(rows)

    assert summary["unexamined"] == ["webgoat"]
    assert summary["vulnerable"] == 0
    assert summary["vulnerable_overall"] is None
    assert summary["separation"] is None
    # Still counted and still reported in the whole-corpus figure, just not
    # in the one the bands are chosen from.
    assert summary["measured"] == 2
    assert summary["reported_overall"]["max"] == 5.0


def test_a_corpus_with_nothing_examined_reports_no_distribution_at_all():
    """Four unexamined repositories once held the corpus median up from 3.38
    to 4.37. With *every* repository unexamined there is nothing to report,
    and every distribution has to come back absent rather than as a zero or a
    set of perfect scores."""
    harness = _harness()
    rows = [
        _row(harness, "gson", overall=5.0, language="java"),
        _row(harness, "webgoat", overall=5.0, kind="vulnerable-by-design", language="java"),
    ]

    summary = harness.summarize(rows)

    assert summary["examined"] == 0
    assert summary["examined_overall"] is None
    assert summary["examined_worst_normalized"] is None
    assert summary["maintained_overall"] is None
    assert summary["vulnerable_overall"] is None
    assert summary["separation"] is None
    assert sorted(summary["unexamined"]) == ["gson", "webgoat"]


def test_an_empty_corpus_reports_no_percentiles_rather_than_zeroes():
    """`--only` with a name that matches nothing leaves no rows. A percentile
    block of zeroes for that run would be a distribution over nothing, and it
    would be written into `results.json` looking like a successful study."""
    harness = _harness()

    summary = harness.summarize([])

    assert summary["repositories"] == 0
    assert summary["measured"] == 0
    assert summary["reported_overall"] == {}
    assert "median" not in summary["reported_overall"]
    assert summary["maintained_overall"] is None
    assert summary["separation"] is None
    assert summary["letters"] == {}


def test_a_repository_that_failed_is_named_and_kept_out_of_every_figure():
    """A failed audit is not a clean one, and it is not an unexamined one
    either. It has no grade at all, so it must not reach a percentile, a
    letter count or the unexamined list — it goes in `failed`."""
    harness = _harness()
    rows = [
        _row(harness, "django", overall=2.0),
        {"name": "broken", "error": "RuntimeError: no report produced"},
    ]

    summary = harness.summarize(rows)

    assert summary["failed"] == ["broken"]
    assert summary["repositories"] == 2
    assert summary["measured"] == 1
    assert summary["reported_overall"]["median"] == 2.0
    assert summary["letters"] == {"B": 1}
    assert "broken" not in summary["unexamined"]
    assert "broken" not in [name for name, _letter in summary["maintained_letters"]]


def test_the_letter_histogram_counts_each_measured_repository_exactly_once():
    harness = _harness()
    rows = [
        _row(harness, "a", overall=3.5, letter="B"),
        _row(harness, "b", overall=3.6, letter="B"),
        _row(harness, "goat", overall=0.0, letter="F", kind="vulnerable-by-design"),
    ]

    summary = harness.summarize(rows)

    assert summary["letters"] == {"B": 2, "F": 1}
    assert sum(summary["letters"].values()) == summary["measured"]


def test_each_repository_keeps_its_own_letter_in_the_per_name_listing():
    """The letters are sorted by name. Sorting the names and the letters
    independently would produce a plausible-looking table in which the worst
    repository is credited with the best grade — the listing is read by hand
    when a corpus result is being checked, so it has to be the pairing."""
    harness = _harness()
    rows = [
        _row(harness, "alpha", overall=0.5, letter="F"),
        _row(harness, "zeta", overall=4.8, letter="A"),
    ]

    summary = harness.summarize(rows)

    assert summary["maintained_letters"] == [("alpha", "F"), ("zeta", "A")]


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def _entry(name: str, *, language: str = "python", kind: str | None = None) -> dict:
    entry = {
        "name": name,
        "url": f"https://example.invalid/{name}.git",
        "commit": "0" * 40,
        "language": language,
    }
    if kind is not None:
        entry["kind"] = kind
    return entry


def _payload(
    *,
    overall: float,
    letter: str = "B",
    loc: int = 10_000,
    scanners: tuple[str, ...] = ("bandit", "gitleaks"),
) -> dict:
    """A report of the shape `measure` and `variants` both read."""
    return {
        "score": {
            "loc_scanned": loc,
            "overall": overall,
            "letter": letter,
            "worst_category": "code_vulnerabilities",
            "per_severity_count": {"high": 1},
        },
        "findings": [],
        "coverage": {
            "status": "complete",
            "scanners": [{"name": name, "outcome": "completed"} for name in scanners],
        },
        "reported_not_scored": {"test_tree": {"count": 3, "loc": 500}},
    }


class _Study:
    """One `main()` run with the network and the CLI substituted out."""

    def __init__(self, rc, harness, out_path, out, audited, config, work, stdout):
        self.rc = rc
        self.harness = harness
        self.out_path = out_path
        self.out = out
        self.audited = audited
        self.config = config
        self.work = work
        self.stdout = stdout


def _run(
    tmp_path,
    monkeypatch,
    capsys,
    entries: list[dict],
    payloads: dict[str, dict],
    *,
    only: str = "",
    work: Path | None = None,
    fetch_fails: tuple[str, ...] = (),
    harness=None,
) -> _Study:
    harness = harness or _harness()
    corpus = tmp_path / "corpus.json"
    corpus.write_text(json.dumps({"version": 1, "repositories": entries}), encoding="utf-8")
    work = work or (tmp_path / "work")
    out_path = tmp_path / "results.json"
    config = tmp_path / "calibration-config.json"
    config.write_text(json.dumps({"version": 1}), encoding="utf-8")

    audited: list[dict] = []

    def fetch(entry: dict, work_dir: Path) -> Path:
        if entry["name"] in fetch_fails:
            raise RuntimeError(f"{entry['name']}: fetch failed: offline")
        return Path(work_dir) / entry["name"]

    def audit(target: Path, report: Path, config_path: Path) -> dict:
        audited.append(
            {"target": Path(target), "report": Path(report), "config": Path(config_path)}
        )
        payload = payloads[Path(report).stem]
        Path(report).write_text(json.dumps(payload), encoding="utf-8")
        return payload

    monkeypatch.setattr(harness, "fetch", fetch)
    monkeypatch.setattr(harness, "audit", audit)

    argv = [
        "calibrate.py",
        "--corpus",
        str(corpus),
        "--work",
        str(work),
        "--out",
        str(out_path),
        "--config",
        str(config),
    ]
    if only:
        argv += ["--only", only]
    monkeypatch.setattr(sys, "argv", argv)

    rc = harness.main()
    captured = capsys.readouterr().out
    out = json.loads(out_path.read_text(encoding="utf-8")) if out_path.exists() else None
    return _Study(rc, harness, out_path, out, audited, config, work, captured)


def test_the_run_writes_a_results_file_naming_the_inputs_it_used(tmp_path, monkeypatch, capsys):
    """`results.json` is the evidence D16 and D17 rest on. A result that does
    not say which corpus, which config and which scanner set produced it
    cannot be re-run, and the whole point of the harness is that the study is
    reproducible."""
    study = _run(
        tmp_path,
        monkeypatch,
        capsys,
        [_entry("django")],
        {"django": _payload(overall=3.5)},
    )

    assert study.rc == 0
    assert study.out["corpus"] == str(tmp_path / "corpus.json")
    assert study.out["config"] == str(study.config)
    assert study.out["scanner_set"] == study.harness.SCANNER_SET
    assert [row["name"] for row in study.out["rows"]] == ["django"]


def test_every_repository_is_audited_under_the_one_config(tmp_path, monkeypatch, capsys):
    """Two repositories measured under different `exclude_patterns` are not a
    distribution — they are unrelated numbers. The config reaching every audit
    unchanged is what makes the corpus comparable, and `--config` is mandatory
    in `audit()` for that reason."""
    study = _run(
        tmp_path,
        monkeypatch,
        capsys,
        [_entry("django"), _entry("flask")],
        {"django": _payload(overall=3.5), "flask": _payload(overall=1.0)},
    )

    assert [call["config"] for call in study.audited] == [study.config, study.config]
    # And each repository writes its own report, so one cannot read another's.
    assert [call["report"].name for call in study.audited] == ["django.json", "flask.json"]
    assert [call["target"].name for call in study.audited] == ["django", "flask"]


def test_only_audits_just_the_repositories_it_names(tmp_path, monkeypatch, capsys):
    study = _run(
        tmp_path,
        monkeypatch,
        capsys,
        [_entry("django"), _entry("flask"), _entry("httpx")],
        {"flask": _payload(overall=1.0)},
        only="flask",
    )

    assert [call["target"].name for call in study.audited] == ["flask"]
    assert [row["name"] for row in study.out["rows"]] == ["flask"]
    assert study.out["summary"]["repositories"] == 1


def test_one_repository_failing_does_not_end_the_study(tmp_path, monkeypatch, capsys):
    """A corpus run takes hours. Dying on the first unreachable remote would
    throw away every repository after it, so the failure is recorded against
    that name and the loop continues — and the recorded row carries the
    exception, not a grade."""
    study = _run(
        tmp_path,
        monkeypatch,
        capsys,
        [_entry("django"), _entry("flask"), _entry("httpx")],
        {"django": _payload(overall=3.5), "httpx": _payload(overall=4.0)},
        fetch_fails=("flask",),
    )

    rows = {row["name"]: row for row in study.out["rows"]}
    assert study.out["summary"]["failed"] == ["flask"]
    assert "measure" not in rows["flask"]
    assert rows["flask"]["error"].startswith("RuntimeError: flask: fetch failed")
    assert "measure" in rows["django"]
    assert "measure" in rows["httpx"]
    assert [call["target"].name for call in study.audited] == ["django", "httpx"]
    assert "FAILED" in study.stdout


def test_a_run_with_a_failed_repository_exits_nonzero(tmp_path, monkeypatch, capsys):
    """PRODUCT BUG — `main` returned 0 however many repositories failed.

    The loop deliberately survives one unreachable remote, which is right:
    a corpus run takes hours and dying on the first failure throws away
    every repository after it. But surviving is not succeeding. `main`
    returned 0 unconditionally, so a run that fetched nothing at all, wrote
    a `results.json` with an empty distribution and printed FAILED nineteen
    times still reported success to its caller.

    That matters because of what this script is for. D17's published
    figures — AUC, separation, the maintained median — are the evidence for
    the grade scale, and promise P6 is that every empirical claim here is
    reproducible from checked-in pinned inputs. A silent partial run
    produces figures over a smaller corpus than the one named, and the exit
    code is the only thing that could say so. An exit code that lies is the
    exact defect class this product exists to catch.

    Any failure is enough. A partial corpus is not a corpus, so this does
    not wait for all of them to fail.
    """
    study = _run(
        tmp_path,
        monkeypatch,
        capsys,
        [_entry("django"), _entry("flask"), _entry("httpx")],
        {"django": _payload(overall=3.5), "httpx": _payload(overall=4.0)},
        fetch_fails=("flask",),
    )

    assert study.out["summary"]["failed"] == ["flask"]
    assert study.rc != 0, (
        "a run with a failed repository reported success; its figures are "
        "derived from a smaller corpus than the one it was given"
    )


def test_a_run_where_every_repository_failed_exits_nonzero(tmp_path, monkeypatch, capsys):
    """The degenerate case, which produced the most confident wrong answer.

    With every fetch failing there is no distribution at all, so `main`
    takes the no-median branch and returns early — and that branch also
    returned 0. The run printed "no distribution to calibrate from", which
    reads as a legitimate outcome for an all-Java corpus, and exited
    successfully having measured nothing.
    """
    study = _run(
        tmp_path,
        monkeypatch,
        capsys,
        [_entry("django"), _entry("flask")],
        {},
        fetch_fails=("django", "flask"),
    )

    assert study.out["summary"]["failed"] == ["django", "flask"]
    assert study.rc != 0, "a run that measured nothing reported success"


def test_a_clean_run_still_exits_zero(tmp_path, monkeypatch, capsys):
    """The falsifier. `return 1` everywhere would satisfy both tests above."""
    study = _run(
        tmp_path,
        monkeypatch,
        capsys,
        [_entry("django"), _entry("pygoat", kind="vulnerable-by-design")],
        {"django": _payload(overall=3.5), "pygoat": _payload(overall=0.0, letter="F")},
    )

    assert study.out["summary"]["failed"] == []
    assert study.rc == 0


def test_the_printed_headline_is_the_maintained_median_not_the_pooled_one(
    tmp_path, monkeypatch, capsys
):
    """The pooled median moved with the number of training applications in the
    list. The headline the operator reads has to be the maintained one, and
    the vulnerable median is printed beside it rather than mixed into it."""
    study = _run(
        tmp_path,
        monkeypatch,
        capsys,
        [
            _entry("django"),
            _entry("flask"),
            _entry("pygoat", kind="vulnerable-by-design"),
            _entry("nodegoat", kind="vulnerable-by-design"),
        ],
        {
            "django": _payload(overall=3.5),
            "flask": _payload(overall=4.5),
            "pygoat": _payload(overall=0.0, letter="F"),
            "nodegoat": _payload(overall=0.5, letter="F"),
        },
    )

    assert "Maintained median: 4.0" in study.stdout
    assert "Vulnerable-by-design median: 0.25" in study.stdout
    # The pooled median of the same four grades.
    assert "2.0 →" not in study.stdout


def test_an_overlap_is_printed_as_an_overlap(tmp_path, monkeypatch, capsys):
    """The sign of the separation is the verdict. Printing "+" wording for a
    negative figure would report that a band edge can separate the halves when
    it cannot, which is the one claim D17 exists to support."""
    study = _run(
        tmp_path,
        monkeypatch,
        capsys,
        [_entry("django"), _entry("pygoat", kind="vulnerable-by-design")],
        {"django": _payload(overall=1.0), "pygoat": _payload(overall=2.5)},
    )

    assert "Separation: -1.50" in study.stdout
    assert "THE POPULATIONS OVERLAP" in study.stdout


def test_a_clean_separation_is_printed_as_one(tmp_path, monkeypatch, capsys):
    study = _run(
        tmp_path,
        monkeypatch,
        capsys,
        [_entry("django"), _entry("pygoat", kind="vulnerable-by-design")],
        {"django": _payload(overall=3.5), "pygoat": _payload(overall=0.5, letter="F")},
    )

    assert "Separation: +3.00" in study.stdout
    assert "do not overlap" in study.stdout
    assert "THE POPULATIONS OVERLAP" not in study.stdout


def test_a_run_with_no_examined_maintained_repository_says_so_and_prints_no_median(
    tmp_path, monkeypatch, capsys
):
    """Six repositories in the real corpus have no scanner that reads their
    language, report zero findings and grade A+. A run consisting only of
    those must print no median at all — printing one would be P7 broken inside
    the study that exists to check the scale."""
    study = _run(
        tmp_path,
        monkeypatch,
        capsys,
        [_entry("gson", language="java"), _entry("commons-lang", language="java")],
        {
            "gson": _payload(overall=5.0, letter="A+", scanners=("gitleaks",)),
            "commons-lang": _payload(overall=5.0, letter="A+", scanners=("gitleaks",)),
        },
    )

    assert study.rc == 0
    assert "no distribution to calibrate from" in study.stdout
    assert "Maintained median" not in study.stdout
    assert "Separation" not in study.stdout
    # The measurements are still written down; only the headline is withheld.
    assert study.out["summary"]["examined"] == 0
    assert sorted(study.out["summary"]["unexamined"]) == ["commons-lang", "gson"]


def test_the_unexamined_repositories_are_counted_out_loud(tmp_path, monkeypatch, capsys):
    """Every figure above that line excludes them, so the line has to appear
    whenever any repository was skipped — otherwise the distribution looks
    like it covered the whole corpus."""
    study = _run(
        tmp_path,
        monkeypatch,
        capsys,
        [_entry("django"), _entry("flask"), _entry("gson", language="java")],
        {
            "django": _payload(overall=3.5),
            "flask": _payload(overall=4.5),
            "gson": _payload(overall=5.0, letter="A+", scanners=("gitleaks",)),
        },
    )

    assert "1 of 3 repositories were not examined" in study.stdout
    assert "UNEXAMINED" in study.stdout, "the per-repository line did not flag it either"
    assert study.out["summary"]["unexamined"] == ["gson"]


def test_the_examined_flag_is_recorded_per_repository(tmp_path, monkeypatch, capsys):
    """`results.json` is read long after the run. Each row has to carry
    whether a scanner read it, so a later reader cannot mistake a clean
    unexamined repository for a clean examined one."""
    study = _run(
        tmp_path,
        monkeypatch,
        capsys,
        [_entry("django"), _entry("gson", language="java")],
        {
            "django": _payload(overall=3.5),
            "gson": _payload(overall=5.0, letter="A+", scanners=("gitleaks",)),
        },
    )

    rows = {row["name"]: row for row in study.out["rows"]}
    assert rows["django"]["examined"] is True
    assert rows["gson"]["examined"] is False


def test_an_only_run_does_not_report_variants_for_repositories_it_skipped(
    tmp_path, monkeypatch, capsys
):
    """FAILING — a real defect, left for the implementer.

    `variants()` globs every `*.json` under the work directory's `_reports`,
    and the clones and their reports are deliberately left in place so a
    re-run is cheap. So a `--only` run writes a `results.json` whose `rows`
    cover the named repositories while its `variants` block — the
    `median_worst_normalized` and `median_grade_at_current_slope` figures that
    D16 chose the slope from — is computed over whatever reports an earlier
    run happened to leave behind, at whatever ruleset and scanner versions
    were current then.

    This is the same stale-report failure `audit()` carries a paragraph about
    and `test_a_stale_report_cannot_stand_in_for_a_failed_audit` pins: a file
    left over from an earlier run standing in for this one. It was fixed where
    one repository reads its own report and not where the variants read all of
    them.

    Here `flask` is audited alone after a full run, and its variant medians are
    still computed across `django` too.
    """
    entries = [_entry("django"), _entry("flask")]
    payloads = {"django": _payload(overall=3.5, loc=50_000), "flask": _payload(overall=1.0)}
    work = tmp_path / "work"

    first = _run(tmp_path, monkeypatch, capsys, entries, payloads, work=work)
    assert set(first.out["summary"]["variants"]["per_repository"]) == {"django", "flask"}

    second = _run(
        tmp_path,
        monkeypatch,
        capsys,
        entries,
        {"flask": payloads["flask"]},
        only="flask",
        work=work,
    )

    assert [row["name"] for row in second.out["rows"]] == ["flask"]
    assert set(second.out["summary"]["variants"]["per_repository"]) == {"flask"}, (
        "the variants block reports repositories this run never audited"
    )
