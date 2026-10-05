"""`COMPLETE` must mean something was read, not that every scanner ran.

**A correction first, because the first version of this file asserted
something false.** It claimed that on `calibration/.corpus/gin` — 7,146 lines
of Go reporting `coverage: complete` and `code_vulnerabilities: 5.0` — *"not
one of those scanners reads Go"*. Semgrep does: its offline profile carries
five Go rules (command injection, weak hash, weak cipher, TLS verification
disabled, weak random) and they fire on the shipped Go fixture. So Go was
read, by five rules and no dedicated scanner.

The same error broke a real test. The map was lifted from
`calibration/calibrate.py`, where `python: ("bandit",)` is a proxy for
coverage *depth* inside a study with a fixed scanner set. Read as "what reads
Python at all" it is false — `builtin_rules` is Python-only and finds plenty
— and `test_a_grade_is_issued_only_when_a_declared_scanner_set_actually_ran`
failed, correctly, by declaring `builtin_rules` and nothing else.

**So this now makes the weaker claim that is true:** a language is flagged
only when *nothing* in the run read it. That still catches C, Rust, PHP and
shell, which no scanner in this floor reads at all.

**What it deliberately does not do** is answer the depth question the study
is really asking — whether five generic rules is coverage or a floor.
`COMPLETE` and `PARTIAL` cannot express that, and inventing a third state is
a product decision rather than a bug fix. The `gin` observation stands as a
limitation to be decided, not as a defect fixed here.

Degrades to PARTIAL, not FAILED: PARTIAL withholds the *verified* grade and
leaves `require_scanners` alone. FAILED would refuse to audit any repository
containing a shell script.
"""

from __future__ import annotations

from secure_code_audit.scanner_status import (
    LANGUAGE_SCANNERS,
    CoverageStatus,
    ScannerExecution,
    ScannerOutcome,
    evaluate_coverage,
)


def _ran(name: str) -> ScannerExecution:
    return ScannerExecution(name=name, outcome=ScannerOutcome.COMPLETED)


# --- the map ---------------------------------------------------------------


def test_the_map_names_every_scanner_that_really_reads_the_language():
    """Not the study's map. Each of these was verified by running the tool.

    `builtin_rules` is Python-only and finds real findings; semgrep's offline
    profile carries rules for Python, JavaScript, TypeScript, Go, Ruby and
    Java, and the Go ones fire on the shipped fixture. Omitting them is what
    made the first version of this file assert that nothing reads Go.
    """
    assert "builtin_rules" in LANGUAGE_SCANNERS["python"]
    assert "semgrep" in LANGUAGE_SCANNERS["python"]
    assert "semgrep" in LANGUAGE_SCANNERS["go"], "the offline profile has five Go rules"
    assert "semgrep" in LANGUAGE_SCANNERS["java"], "and five Java rules"
    assert "njsscan" in LANGUAGE_SCANNERS["javascript"]
    assert "rubocop" in LANGUAGE_SCANNERS["ruby"]
    # Nothing in the floor reads shell for code defects, so there is no name
    # to suggest. An empty tuple is the honest entry.
    assert LANGUAGE_SCANNERS["shell"] == ()


# --- the behaviour ---------------------------------------------------------


def test_a_language_no_scanner_reads_degrades_coverage():
    """The defect, at the smallest scale that shows it."""
    report = evaluate_coverage([_ran("bandit")], required=[], languages=["shell"])

    assert report.status is CoverageStatus.PARTIAL, report.status
    assert report.unread_languages, "the language went unnamed"


def test_the_reason_names_the_language_and_what_would_read_it():
    """An operator needs to know what to install, not just that something is missing."""
    report = evaluate_coverage([_ran("bandit")], required=[], languages=["shell"])

    joined = " ".join(report.unread_languages)
    assert "shell" in joined.lower(), joined
    assert "no scanner in this floor reads it" in joined, joined


def test_a_language_with_a_reader_that_ran_is_covered_even_without_a_dedicated_scanner():
    """Go with semgrep is read — thinly, by five rules, but read.

    This is the case the first version of this file got wrong. Whether five
    generic rules *should* count is the depth question, and it is not settled
    here.
    """
    report = evaluate_coverage([_ran("semgrep")], required=[], languages=["go"])

    assert report.status is CoverageStatus.COMPLETE, report.status
    assert report.unread_languages == ()


def test_a_covered_language_does_not_degrade_anything():
    """The falsifier. Python with bandit is covered and must stay COMPLETE."""
    report = evaluate_coverage([_ran("bandit")], required=[], languages=["python"])

    assert report.status is CoverageStatus.COMPLETE, report.status
    assert report.unread_languages == ()


def test_a_language_absent_from_the_tree_is_never_named():
    """Only languages actually present can be unread.

    Without this the check would warn every Python repository about Go, which
    is the noise that gets a warning switched off.
    """
    report = evaluate_coverage([_ran("bandit")], required=[], languages=["python"])

    assert report.unread_languages == ()


def test_an_unknown_language_is_not_treated_as_unread():
    """YAML, JSON and Markdown are not code-vulnerability languages.

    They are covered on other axes by checkov and trivy, and the map is
    deliberately only the languages this floor claims to scan for code
    defects. Treating every extension as an unread language would make
    PARTIAL the permanent state of every repository.
    """
    report = evaluate_coverage([_ran("bandit")], required=[], languages=["python", "yaml"])

    assert report.status is CoverageStatus.COMPLETE
    assert report.unread_languages == ()


def test_no_languages_passed_leaves_behaviour_exactly_as_before():
    """Callers that do not supply languages must be unaffected.

    The parameter is additive: every existing call site, and every consumer
    reading an older report, keeps its meaning.
    """
    report = evaluate_coverage([_ran("bandit")], required=[])

    assert report.status is CoverageStatus.COMPLETE
    assert report.unread_languages == ()


def test_a_required_scanner_failure_still_outranks_an_unread_language():
    """FAILED is about a promise an operator made; PARTIAL is about breadth.

    A required scanner that did not run must keep failing the gate, and the
    unread language must not downgrade that to merely partial.
    """
    broken = ScannerExecution(name="trivy", outcome=ScannerOutcome.FAILED, reason="429")

    report = evaluate_coverage([broken], required=["trivy"], languages=["shell"])

    assert report.status is CoverageStatus.FAILED, report.status
    assert report.failures, "the required-scanner failure was lost"
    assert report.unread_languages, "the unread language was lost"


def test_the_language_scanner_actually_running_covers_it():
    """The other falsifier: install the scanner and the language is covered."""
    report = evaluate_coverage(
        [_ran("bandit"), _ran("gosec")], required=[], languages=["go", "python"]
    )

    assert report.status is CoverageStatus.COMPLETE, report.status
    assert report.unread_languages == ()


def test_a_language_scanner_that_ran_but_failed_does_not_cover_it():
    """Running is not covering — the same distinction `COVERING_OUTCOMES` makes."""
    broken = ScannerExecution(name="gosec", outcome=ScannerOutcome.FAILED, reason="boom")

    report = evaluate_coverage([broken], required=[], languages=["shell"])

    assert report.unread_languages, "a failed gosec was treated as Go coverage"
