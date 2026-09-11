"""Scan history, because movement is the score's only real use.

Marshall: *"The scoring model is really only valuable for visualizing
patterns over time if the score changes. Otherwise its just a score.
wooopee."*

So the requirements are modest and the failure modes are all about not
losing or misreporting history: append rather than rewrite, survive a bad
line, and never invent a comparison that did not happen.
"""

from __future__ import annotations

from dataclasses import replace

from secure_code_audit.history import SCHEMA, Entry, append, read, trend


def _entry(score: float | None, letter: str | None = "A", at: str = "2026-09-10T00:00:00+00:00"):
    return Entry(
        at=at,
        version="0.5.0",
        score=score,
        letter=letter,
        coverage_complete=True,
        gate_passed=True,
        finding_count=0,
        loc_scanned=1000,
    )


# ---------------------------------------------------------------------------
# Round trip
# ---------------------------------------------------------------------------


def test_a_run_is_appended_and_read_back(tmp_path):
    path = tmp_path / "history.jsonl"
    append(path, _entry(4.2, "A-"))

    (row,) = read(path)

    assert (row.score, row.letter, row.schema) == (4.2, "A-", SCHEMA)


def test_runs_accumulate_rather_than_overwrite(tmp_path):
    """The whole point is the sequence. A writer that replaced the file
    would leave a trend of length one forever."""
    path = tmp_path / "history.jsonl"
    for n in range(5):
        append(path, _entry(float(n)))

    assert [e.score for e in read(path)] == [0.0, 1.0, 2.0, 3.0, 4.0]


def test_the_directory_is_created_on_demand(tmp_path):
    path = tmp_path / "nested" / "deeper" / "history.jsonl"
    append(path, _entry(3.0))

    assert len(read(path)) == 1


def test_reading_a_missing_history_is_not_an_error(tmp_path):
    assert read(tmp_path / "nope.jsonl") == []


# ---------------------------------------------------------------------------
# Durability
# ---------------------------------------------------------------------------


def test_one_corrupt_line_does_not_destroy_the_history(tmp_path):
    """This file is appended to by every run and may be hand-edited or
    merged by git. A half-written line should cost one run, not all of them.
    """
    path = tmp_path / "history.jsonl"
    append(path, _entry(1.0))
    with path.open("a", encoding="utf-8") as handle:
        handle.write('{"at": "truncated"\n')
    append(path, _entry(2.0))

    assert [e.score for e in read(path)] == [1.0, 2.0]


def test_an_unknown_key_from_a_newer_version_is_ignored(tmp_path):
    """An old reader must survive a new writer rather than refusing the
    file outright."""
    path = tmp_path / "history.jsonl"
    with path.open("w", encoding="utf-8") as handle:
        handle.write(
            '{"at":"2026-01-01T00:00:00+00:00","version":"9.9.9","score":3.0,'
            '"letter":"B","coverage_complete":true,"gate_passed":true,'
            '"finding_count":1,"loc_scanned":10,"a_field_from_the_future":42}\n'
        )

    (row,) = read(path)
    assert row.score == 3.0


def test_an_unwritable_path_does_not_fail_the_audit(tmp_path):
    """History is a convenience. A read-only checkout is not a reason to
    throw away the security report the operator actually asked for."""
    blocker = tmp_path / "history.jsonl"
    blocker.parent.mkdir(exist_ok=True)
    (tmp_path / "blocked").write_text("i am a file", encoding="utf-8")

    append(tmp_path / "blocked" / "history.jsonl", _entry(1.0))  # must not raise


# ---------------------------------------------------------------------------
# The trend line
# ---------------------------------------------------------------------------


def test_no_history_says_so_rather_than_guessing():
    assert "no scored history" in trend([])


def test_the_first_run_has_nothing_to_compare_against():
    assert "first scored run" in trend([_entry(4.0)])


def test_a_drop_is_reported_with_its_size():
    line = trend([_entry(5.0, "A+"), _entry(2.0, "C")])

    assert "down" in line and "3.00" in line


def test_a_recovery_is_reported_as_movement_up():
    line = trend([_entry(1.0, "D"), _entry(4.5, "A")])

    assert "up" in line and "3.50" in line


def test_a_steady_score_is_reported_as_unchanged():
    """Six months at B- is information too — it says the gate is holding."""
    line = trend([_entry(3.0, "B") for _ in range(6)])

    assert "unchanged" in line and "6 scored runs" in line


def test_an_unscored_run_is_not_treated_as_a_drop_to_zero():
    """A run whose coverage was too thin to grade has no number. Plotting
    its absent score as 0.0 would report a collapse that did not happen —
    the same "no evidence is not a bad grade" rule the product rests on.
    """
    entries = [_entry(4.0, "A-"), _entry(None, None), _entry(4.0, "A-")]

    line = trend(entries)

    assert "unchanged" in line
    assert "down" not in line


def test_an_all_unscored_history_reports_nothing_rather_than_zero():
    assert "no scored history" in trend([_entry(None, None), _entry(None, None)])


def test_the_unscored_runs_are_still_recorded(tmp_path):
    """Not scoring is a fact about the run worth keeping — it is how an
    operator notices their scanners have been missing for a fortnight."""
    path = tmp_path / "history.jsonl"
    append(path, replace(_entry(None, None), coverage_complete=False))

    (row,) = read(path)
    assert row.score is None and row.coverage_complete is False
