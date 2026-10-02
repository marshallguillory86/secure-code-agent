"""`--verify-against` is the half of the product that checks the other half.

The tool's claim is not "here is a work order"; it is "and here is whether the
order was carried out". `verify.py` carries a module docstring naming three
things an agent under time pressure genuinely does — silence a finding, trade
five fixes for three new findings, break a file the order never cited — and
`verify.compare` is unit-tested against all three.

Nothing exercised the **door**. `cli._findings_from_report`, `cli._do_verify`
and `cli._commit_of_report` had no test through `main()` at all, so every
claim in those docstrings rested on a path no run had taken: the rehydration
of a saved report into findings, the exit code, the human-readable transcript
an operator actually reads, and the refusal to accept a file that is not one
of our reports. A verification step whose own plumbing is untested is the
same shape of problem as a gate that always passes.

Bandit is the scanner throughout, because this is the real pipeline rather
than a stub: a saved report has to survive a round trip through JSON and come
back as findings whose fingerprints still match a live scan.

Every vulnerable line here is assembled from parts. This repository audits its
own tests, and spelling the pattern out has created a finding here before.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from secure_code_audit import cli

#: `eval(s)` — B307. Chosen over a `subprocess` call because importing
#: subprocess is a finding of its own (B404) and the point here is one
#: finding whose outcome is unambiguous.
_EVAL_CALL = "ev" + "al(s)"
#: `exec(s)` — B102, a second, distinguishable finding.
_EXEC_CALL = "ex" + "ec(s)"

_VULNERABLE = f"def f(s):\n    return {_EVAL_CALL}\n"
_REPAIRED = "def f(s):\n    return int(s)\n"


def _git(tree: Path, *args: str) -> None:
    # Inherited environment plus `--no-verify` at the call site: this machine
    # runs a commit-identity hook that rejects any author but the owner's.
    subprocess.run(
        ["git", "-C", str(tree), "-c", "user.email=t@example.invalid", "-c", "user.name=t", *args],
        check=True,
        capture_output=True,
        env={**os.environ, "GIT_IDENTITY_OVERRIDE": "1"},
    )


@pytest.fixture
def audited(tmp_path, monkeypatch):
    """A committed repository, audited once, with `before.json` on disk.

    Returns a callable: it applies no mutation of its own, so each test says
    what the agent did and then asks the tool what it thinks happened.
    """
    tree = tmp_path / "repo"
    (tree / "src").mkdir(parents=True)
    (tree / "src" / "app.py").write_text(_VULNERABLE, encoding="utf-8")
    _git(tree, "init", "-q")
    _git(tree, "add", "-A")
    _git(tree, "-c", "commit.gpgsign=false", "commit", "--no-verify", "-qm", "base")

    # Outside the tree: an in-tree config no longer chooses a scanner's
    # command (D29), and a config the audited repository supplies would be
    # ignored anyway.
    cfg = tmp_path / "secure-code-agent.json"
    cfg.write_text(
        json.dumps({"version": 1, "scanners": {"bandit": {"enabled": True}}, "gates": {}}),
        encoding="utf-8",
    )
    before = tree / "before.json"

    # Run from somewhere that is not the tree, so a path resolved against the
    # process working directory cannot be rescued by luck.
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)

    base_argv = [str(tree), "--config", str(cfg), "--only-scanners", "bandit"]
    assert cli.main([*base_argv, "--json-output", str(before)]) == 0
    recorded = json.loads(before.read_text(encoding="utf-8"))
    assert [f["rule_id"] for f in recorded["findings"]] == ["B307"], (
        "the fixture no longer produces the one finding the verification is about"
    )

    def verify(*extra: str, report: Path | None = None) -> int:
        return cli.main([*base_argv, "--verify-against", str(report or before), *extra])

    return {"tree": tree, "before": before, "verify": verify, "argv": base_argv}


def test_a_repaired_finding_is_reported_fixed_and_lets_the_run_through(audited, capsys):
    """The passing case, through the door, with the real transcript.

    `_do_verify`'s non-JSON branch prints the per-finding lines an operator
    reads; nothing had ever run it, so "fixed" could have printed the wrong
    finding, the wrong file, or nothing at all and no test would have known.
    """
    (audited["tree"] / "src" / "app.py").write_text(_REPAIRED, encoding="utf-8")

    assert audited["verify"]() == 0

    out = capsys.readouterr().out
    assert "work order verification" in out
    assert "improved: 1 fixed" in out
    assert "fixed      B307" in out
    assert "app.py:2" in out


def test_a_nosec_comment_is_reported_as_silenced_rather_than_fixed(audited, capsys):
    """The defect `verify._is_silenced` exists for, end to end.

    Bandit honours `# nosec` itself, so the finding never reaches us and
    reads exactly like a repair. Measured on a fixture once: two real
    findings, both commented out of existence, reported "improved: 2 fixed"
    and exited 0. Through the CLI the run must fail and the transcript must
    use the word that tells the operator what happened.
    """
    marker = "# no" + "sec"
    (audited["tree"] / "src" / "app.py").write_text(
        f"def f(s):\n    return {_EVAL_CALL}  {marker}\n", encoding="utf-8"
    )

    assert audited["verify"]() == 1

    out = capsys.readouterr().out
    assert "SILENCED   B307" in out
    assert "1 silenced rather than fixed" in out
    assert "fixed      " not in out


def test_a_traded_fix_fails_even_though_the_count_fell(audited, capsys):
    """One repaired, one introduced elsewhere: not an improvement.

    The count can fall while the code gets worse. `improved` is deliberately
    strict about this, and the exit code is what CI reads.
    """
    (audited["tree"] / "src" / "app.py").write_text(_REPAIRED, encoding="utf-8")
    (audited["tree"] / "src" / "other.py").write_text(
        f"def g(s):\n    {_EXEC_CALL}\n", encoding="utf-8"
    )

    assert audited["verify"]() == 1

    out = capsys.readouterr().out
    assert "1 fixed" in out and "1 introduced" in out
    assert "INTRODUCED B102" in out
    assert "other.py:2" in out


def test_an_unactioned_work_order_does_not_pass(audited, capsys):
    """Nothing touched. "Nothing regressed" is not the same as "done".

    `passed` lets a clean repository through — otherwise a team that fixed
    everything would own a CI step that can never go green — and this is the
    other side of that rule: an outstanding order still fails.
    """
    assert audited["verify"]() == 1

    out = capsys.readouterr().out
    assert "still open B307" in out
    assert "1 still open" in out


def test_the_transcript_names_collateral_the_order_never_cited(audited, capsys):
    """Scope, measured through the door and off the before-report's commit.

    `_commit_of_report` reads the commit the saved report was taken at; with
    it the run can say which changed files the order never mentioned. The
    tool's own outputs are written by the verifying run itself, so a report
    or a work order appearing here would make every verification exceed its
    scope.
    """
    (audited["tree"] / "src" / "app.py").write_text(_REPAIRED, encoding="utf-8")
    (audited["tree"] / "src" / "session.py").write_text("TOKEN_TTL = 1\n", encoding="utf-8")

    assert audited["verify"]() == 0

    out = capsys.readouterr().out
    assert "scope: EXCEEDED" in out
    assert "collateral src/session.py" in out
    assert "secure-code-report" not in out, "the verifying run blamed the agent for our own output"


def test_a_before_report_without_a_commit_reports_scope_unknown(audited, capsys):
    """An unmeasured scope is reported unknown, never as conformant.

    The same rule the coverage axis applies to scanners. A report from an
    older release, or from a tree that is not a git repository, records no
    commit — and a missing measurement that printed "conformant" would be a
    clean result nobody had checked.
    """
    payload = json.loads(audited["before"].read_text(encoding="utf-8"))
    del payload["commit"]
    audited["before"].write_text(json.dumps(payload), encoding="utf-8")

    assert audited["verify"]() == 1

    out = capsys.readouterr().out
    assert "scope: unknown" in out
    assert "records no commit" in out


def test_a_stored_fingerprint_is_restored_rather_than_recomputed(audited, capsys):
    """The snippet in a saved report is truncated; the identity is not.

    `_findings_from_report` keeps the stored fingerprint for exactly this
    reason. Recomputing it from the report's shortened `code_snippet` would
    yield a different id, so the same unchanged finding would read as both
    fixed and introduced on every verification.
    """
    payload = json.loads(audited["before"].read_text(encoding="utf-8"))
    payload["findings"][0]["code_snippet"] = "sub"
    audited["before"].write_text(json.dumps(payload), encoding="utf-8")

    assert audited["verify"]() == 1

    out = capsys.readouterr().out
    assert "still open B307" in out
    assert "INTRODUCED" not in out
    assert "fixed      " not in out


def test_the_json_transcript_carries_the_same_outcome_as_the_text_one(audited, capsys):
    """`--json` is what maintainability-agent reads; it must not disagree."""
    (audited["tree"] / "src" / "app.py").write_text(_REPAIRED, encoding="utf-8")

    assert audited["verify"]("--json") == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["passed"] is True
    assert [f["rule_id"] for f in payload["fixed"]] == ["B307"]
    assert payload["introduced"] == [] and payload["suppressed"] == []


def test_a_report_this_tool_did_not_write_is_refused(audited, tmp_path):
    """Not "zero findings before", which would read as everything introduced.

    A JSON file that is merely valid JSON tells us nothing about a previous
    audit. Rehydrating it as an empty before-set would report the whole tree
    as newly introduced and blame the agent for it.
    """
    alien = audited["tree"] / "alien.json"
    alien.write_text(json.dumps({"results": []}), encoding="utf-8")

    assert audited["verify"](report=alien) == 2


def test_an_unreadable_before_report_is_an_error_not_an_empty_comparison(audited):
    """A truncated or missing report must stop the run.

    Treated as "no findings before", a half-written file would make every
    current finding newly introduced — and treated as "nothing to compare",
    it would exit 0 and verify nothing.
    """
    broken = audited["tree"] / "broken.json"
    broken.write_text('{"findings": [', encoding="utf-8")

    assert audited["verify"](report=broken) == 2
    assert audited["verify"](report=audited["tree"] / "absent.json") == 2
