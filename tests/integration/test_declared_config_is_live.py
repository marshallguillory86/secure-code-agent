"""A configuration key that reads as intent and changes nothing is the worst kind.

`test_exclude_patterns_are_live.py` records the original: `**/__pycache__/`
matched nothing, so `.pyc` files were scanned as source for months. An inert
setting has no symptom of its own — it never errors, it reads as a decision
that was made, and the only evidence is findings an operator believed were
already accounted for.

Four keys in `secure-code-agent.json` carried no end-to-end test at all, so
each was that defect waiting to happen:

  * `loc_for_scoring` — the denominator every subtotal is normalised against.
    Inert, it would publish a grade computed against a line count the
    operator explicitly said was wrong.
  * `suppressions_file` — inert, it reads the default `.scignore.yaml` (or
    nothing) while the operator's reviewed entries sit in a file nobody
    opens, and every reviewed finding comes back live.
  * `paths.docs_patterns` — inert, findings in documentation are scored as
    shipped code.
  * `paths.include_extensions` — inert, the denominator counts languages the
    operator excluded from the audit.

Each test below declares the key, runs the real CLI, and reads the answer out
of the JSON report. The vulnerable line is assembled from parts because this
repository audits its own tests.
"""

from __future__ import annotations

import datetime
import json

import pytest

from secure_code_audit import cli

#: `eval(s)` — B307.
_EVAL_CALL = "ev" + "al(s)"
_VULNERABLE = f"def f(s):\n    return {_EVAL_CALL}\n"

#: Inside the loader's maximum TTL, so the entry is accepted rather than
#: rejected for expiring too far out.
_EXPIRES = (datetime.date.today() + datetime.timedelta(days=60)).isoformat()


@pytest.fixture
def audit(tmp_path, monkeypatch):
    """Audit a one-finding tree under a given configuration body."""
    tree = tmp_path / "repo"
    (tree / "src").mkdir(parents=True)
    (tree / "src" / "app.py").write_text(_VULNERABLE, encoding="utf-8")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)

    def run(body: dict) -> dict:
        document = {"version": 1, "scanners": {"bandit": {"enabled": True}}, "gates": {}, **body}
        # Outside the audited tree: the tree's own config does not choose a
        # scanner's command (D29) and is not read for policy either.
        cfg = tmp_path / "secure-code-agent.json"
        cfg.write_text(json.dumps(document), encoding="utf-8")
        out = tmp_path / "report.json"
        assert (
            cli.main(
                [
                    str(tree),
                    "--config",
                    str(cfg),
                    "--only-scanners",
                    "bandit",
                    "--json-output",
                    str(out),
                ]
            )
            == 0
        )
        return json.loads(out.read_text(encoding="utf-8"))

    run.tree = tree  # type: ignore[attr-defined]
    return run


def test_a_declared_line_count_replaces_the_counted_one(audit):
    """Otherwise the grade is normalised against a number already disowned.

    `loc_for_scoring` exists for a repository whose real size the line
    counter cannot see — generated code, a vendored tree, a monorepo slice.
    Declared and inert, the subtotal is divided by the counted lines anyway
    and the operator is shown a grade for a measurement they overrode.
    """
    counted = audit({})["score"]["loc_scanned"]
    assert counted < 100, "the fixture grew; the declared number below is no longer distinctive"

    declared = audit(
        {"loc_for_scoring": {"value": 250_000, "reason": "generated tree, counted upstream"}}
    )

    assert declared["score"]["loc_scanned"] == 250_000


def test_a_declared_suppressions_file_is_the_one_that_is_read(audit):
    """The reviewed entries live where the operator says they live.

    Inert, this key leaves the loader on `.scignore.yaml`: the declared file
    is never opened, every reviewed finding returns as live, and the only
    hint is that the suppressions "stopped working".
    """
    (audit.tree / "reviewed.yaml").write_text(
        "- rule_id: B307\n"
        '  paths: ["src/*.py"]\n'
        "  reason: reviewed fixture\n"
        f"  expires: {_EXPIRES}\n",
        encoding="utf-8",
    )

    report = audit({"suppressions_file": "reviewed.yaml"})

    hits = [f for f in report["findings"] if f["rule_id"] == "B307"]
    assert hits, "bandit reported nothing; the check below would be vacuous"
    assert all(f["suppressed"] for f in hits)


def test_the_default_suppressions_file_is_replaced_rather_than_added_to(audit):
    """Declaring one file must not leave `.scignore.yaml` in the loop.

    If both were read, an operator could not move their suppressions — the
    old file would keep suppressing after they believed they had retired it,
    which is how a lapsed review stays silently in force.
    """
    (audit.tree / ".scignore.yaml").write_text(
        "- rule_id: B307\n"
        '  paths: ["src/*.py"]\n'
        "  reason: retired, kept on disk by accident\n"
        f"  expires: {_EXPIRES}\n",
        encoding="utf-8",
    )
    (audit.tree / "reviewed.yaml").write_text(
        "- rule_id: B999\n"
        '  paths: ["nowhere/*.py"]\n'
        "  reason: matches nothing on purpose\n"
        f"  expires: {_EXPIRES}\n",
        encoding="utf-8",
    )

    report = audit({"suppressions_file": "reviewed.yaml"})

    hits = [f for f in report["findings"] if f["rule_id"] == "B307"]
    assert hits, "bandit reported nothing; the check below would be vacuous"
    assert not any(f["suppressed"] for f in hits), (
        "the retired .scignore.yaml still suppressed a finding"
    )


def test_a_declared_docs_pattern_moves_a_finding_off_the_scored_axis(audit):
    """Documentation is reported, not scored — but only if the key is live.

    `paths.docs_patterns` is how a repository says which paths are prose.
    Inert, a snippet in an example or a runbook is graded as shipped code,
    and the grade is for the wrong thing.
    """
    assert audit({})["findings"][0]["axis"] == "primary", (
        "the finding is already off the primary axis; the check below proves nothing"
    )

    report = audit({"paths": {"docs_patterns": ["src/*.py"]}})

    assert [f["axis"] for f in report["findings"]] == ["documentation"]


def test_a_declared_extension_list_decides_what_the_denominator_counts(audit):
    """The audited languages and the counted lines have to be the same set.

    Inert, the denominator grows with files no scanner in this run can read,
    so adding an unaudited language improves the grade.
    """
    (audit.tree / "src" / "bundle.js").write_text("var x = 1;\n" * 400, encoding="utf-8")

    with_js = audit({"paths": {"include_extensions": [".py", ".js"]}})["score"]["loc_scanned"]
    python_only = audit({"paths": {"include_extensions": [".py"]}})["score"]["loc_scanned"]

    assert with_js - python_only == 400


def test_a_declared_standards_overlay_maps_the_findings(audit, tmp_path):
    """Otherwise the operator's mapping file is a decision that changed nothing.

    `standards_overlay` exists because the curated table is 34 rules and
    Semgrep alone publishes thousands, so mapping a rule meant waiting for a
    package release (§8 question 3). Declared and inert, every finding keeps
    the shipped mapping while the operator believes their file applied — and
    the CWE is what drives OWASP, the Top-25 weight and corroboration, so
    they would be reading somebody else's taxonomy.

    The fixture's one finding is bandit B307, curated as CWE-95. The overlay
    below says CWE-94, its documented parent, which is a mapping an operator
    might genuinely prefer.
    """
    shipped = audit({})["findings"]
    assert [f["rule_id"] for f in shipped] == ["B307"], shipped
    assert shipped[0]["canonical_cwe"] == "CWE-95", "premise: the shipped mapping"

    overlay = tmp_path / "standards-overlay.yaml"
    overlay.write_text(
        "version: 1\n"
        "entries:\n"
        "  - scanner: bandit\n"
        "    rule_id: B307\n"
        "    canonical_cwe: CWE-94\n"
        "    short_desc: Operator maps this to the parent weakness.\n",
        encoding="utf-8",
    )

    mapped = audit({"standards_overlay": str(overlay)})["findings"]

    assert [f["rule_id"] for f in mapped] == ["B307"]
    assert mapped[0]["canonical_cwe"] == "CWE-94", "the declared overlay did not apply"
    assert mapped[0]["short_desc"] == "Operator maps this to the parent weakness."


def test_a_standards_overlay_cannot_move_the_grade(audit, tmp_path):
    """The P3 property, end to end rather than only in the unit.

    D32 is what happens when something outside the instrument can set a
    scoring input: an in-tree `severity_overrides` took a repository from
    0.00/F to 5.00/A+. An overlay is exactly the kind of file an audited tree
    would ship, so it must not reach severity, confidence or category — and
    the proof worth having is that the score is identical with and without
    one.
    """
    before = audit({})
    overlay = tmp_path / "harmless-overlay.yaml"
    overlay.write_text(
        "version: 1\n"
        "entries:\n"
        "  - scanner: bandit\n"
        "    rule_id: B307\n"
        "    canonical_cwe: CWE-94\n"
        "    short_desc: Mapped.\n",
        encoding="utf-8",
    )

    after = audit({"standards_overlay": str(overlay)})

    assert after["findings"][0]["canonical_cwe"] == "CWE-94", "the overlay did apply"
    assert after["findings"][0]["severity"] == before["findings"][0]["severity"]
    assert after["findings"][0]["category"] == before["findings"][0]["category"]
    assert after["score"]["overall"] == before["score"]["overall"], (
        f"an overlay moved the score: {before['score']['overall']} -> {after['score']['overall']}"
    )
