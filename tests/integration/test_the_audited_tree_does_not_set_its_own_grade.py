"""A repository may not grade itself.

D29 settled that a config the audited tree supplies does not choose a
scanner's *command*. It did not cover what that config may say about the
findings, and `severity_overrides` and `category_overrides` were applied
unconditionally — from any config, including one discovered inside the tree
being audited, with no `--trust-target-config`.

Reproduced before this test was written, on a file containing a single
`subprocess` call made with `shell=True` (paraphrased; the fixture below
assembles the real expression from parts):

    honest run                                     0.00  (F)
    plus an in-tree secure-code-agent.json with
    severity_overrides mapping B602 to informational  5.00  (A+)

Same tree, same finding, same scanner. `INFORMATIONAL` carries weight 0.0
in `SEVERITY_WEIGHT`, so re-labelling a finding removes it from the score
without removing it from the report. The audited party moved its own grade
from F to A+.

That is §4 criterion 1 — *a green gate means something* — made falsifiable
by the party with the motive, and it is promise P3 from the other side: P3
refuses an input whose **removal** raises the graded field, and this is an
input whose **addition** raises it.

The intent was already written down. `test_declared_config_is_live.py`
puts its fixture config outside the tree and says why: "the tree's own
config does not choose a scanner's command (D29) and is not read for policy
either." The second half of that sentence was not true of the code.

See D32.
"""

from __future__ import annotations

import json

import pytest

from secure_code_audit import cli
from secure_code_audit.findings import Severity
from secure_code_audit.scoring import SEVERITY_WEIGHT

#: The B602 shell-injection call, HIGH. Assembled from parts because this
#: repository audits its own tests, and spelled out in neither this comment
#: nor the docstring above for the same reason.
_SHELL_CALL = "subprocess.run(cmd, shell=Tr" + "ue)"
_VULNERABLE = f"import subprocess\n\n\ndef run(cmd):\n    return {_SHELL_CALL}\n"

_DOWNGRADE = {
    "version": 1,
    "scanners": {"bandit": {"enabled": True}},
    "gates": {},
    "severity_overrides": {"B602": "informational", "B404": "informational"},
    "category_overrides": {"B602": "policy_docs"},
}

#: The same attack through the denominator. Every category but `secrets` is
#: a density — weighted findings per thousand scanned lines — so a tree that
#: declares its own line count declares its own grade. Measured on this
#: fixture: 0.00/F honestly, **4.999/A+** with this config inside the tree,
#: no flag and no warning. D32 closed `severity_overrides` and
#: `category_overrides` by name and left this one open, which is what comes
#: of listing the keys instead of deriving them from the rule.
_DILUTE = {
    "version": 1,
    "scanners": {"bandit": {"enabled": True}},
    "gates": {},
    "loc_for_scoring": {"value": 10_000_000, "reason": "most of this tree is generated"},
}


@pytest.fixture
def audit(tmp_path, monkeypatch):
    """Audit a tree that carries its own `secure-code-agent.json`."""
    tree = tmp_path / "repo"
    tree.mkdir()
    (tree / "app.py").write_text(_VULNERABLE, encoding="utf-8")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)

    def run(in_tree: dict | None, *, extra_argv: tuple[str, ...] = ()) -> dict:
        in_tree_config = tree / "secure-code-agent.json"
        if in_tree is None:
            in_tree_config.unlink(missing_ok=True)
        else:
            in_tree_config.write_text(json.dumps(in_tree), encoding="utf-8")
        out = tmp_path / f"report-{len(list(tmp_path.glob('report-*.json')))}.json"
        argv = [str(tree), "--only-scanners", "bandit", "--json-output", str(out), *extra_argv]
        assert cli.main(argv) == 0
        return json.loads(out.read_text(encoding="utf-8"))

    return run


def test_informational_is_weightless_which_is_why_this_matters():
    """The premise. Re-labelling is only an attack because the weight is 0."""
    assert SEVERITY_WEIGHT[Severity.INFORMATIONAL] == 0.0
    assert SEVERITY_WEIGHT[Severity.HIGH] > 0.0


def test_an_honest_run_of_the_fixture_grades_badly(audit):
    """The baseline. Without it, the test below could pass on a tree that
    had no finding to downgrade in the first place."""
    report = audit(None)

    severities = {f["rule_id"]: f["severity"] for f in report["findings"]}
    assert severities.get("B602") == "high", severities
    assert report["score"]["overall"] < 1.0, report["score"]["overall"]


def test_an_in_tree_config_cannot_downgrade_a_findings_severity(audit):
    """The tree's own config must not move the grade.

    This is the whole defect: the same tree scored 0.00/F honestly and
    5.00/A+ with an in-tree `severity_overrides`.
    """
    report = audit(_DOWNGRADE)

    severities = {f["rule_id"]: f["severity"] for f in report["findings"]}
    assert severities.get("B602") == "high", (
        "an in-tree config downgraded a HIGH finding to "
        f"{severities.get('B602')!r}; the audited tree set its own grade"
    )
    assert report["score"]["overall"] < 1.0, (
        f"the grade rose to {report['score']['overall']} because the audited tree asked it to"
    )


def test_an_in_tree_config_cannot_recategorise_a_finding(audit):
    """Category drives the per-category rate, and the worst category drives
    the overall — so moving a finding out of `code_vulnerabilities` is the
    same attack by another route."""
    report = audit(_DOWNGRADE)

    categories = {f["rule_id"]: f["category"] for f in report["findings"]}
    assert categories.get("B602") == "code_vulnerabilities", categories


def test_trust_target_config_still_honours_the_overrides(audit):
    """The falsifier, and the escape hatch D29 established.

    Refusing the tree's overrides unconditionally would delete a real
    feature: an operator auditing their *own* repository, with the config
    committed beside the code, is the ordinary case. The flag is how they
    say so, exactly as it works for a scanner's command.
    """
    report = audit(_DOWNGRADE, extra_argv=("--trust-target-config",))

    severities = {f["rule_id"]: f["severity"] for f in report["findings"]}
    assert severities.get("B602") == "informational", (
        "--trust-target-config was passed and the override was still ignored; "
        "the operator's explicit assertion must be honoured"
    )


def test_an_in_tree_config_cannot_declare_its_own_scoring_denominator(audit):
    """`loc_for_scoring` is the grade's denominator, so it is a grading key.

    Every category except `secrets` is a density. Ten million declared lines
    divide one HIGH finding down to nothing, and the tree gets to pick the
    number: 0.00/F honestly, 4.999/A+ with this config and no flag.

    It is the same defect D32 was written to close, reached through the key
    D32 did not list — which is why `_GRADING_KEYS` is now paired against
    what `_refuse_target_policy` actually clears, below.
    """
    report = audit(_DILUTE)

    assert report["score"]["loc_scanned"] < 1_000, (
        f"the audited tree declared {report['score']['loc_scanned']} lines of its own; "
        "the denominator of its grade is not its own to set"
    )
    assert report["score"]["overall"] < 1.0, (
        f"the grade rose to {report['score']['overall']} on a declared line count"
    )


def test_trust_target_config_still_honours_the_declared_line_count(audit):
    """The escape hatch, for the key just closed.

    An operator whose tree really is mostly generated says so with the flag
    or with a config outside the tree, exactly as for the overrides. This is
    the falsifier for the test above: without it, "refuse it always" would
    pass and a real feature would be gone.
    """
    report = audit(_DILUTE, extra_argv=("--trust-target-config",))

    assert report["score"]["loc_scanned"] == 10_000_000, (
        "--trust-target-config was passed and the declared line count was still "
        "ignored; the operator's explicit assertion must be honoured"
    )


def test_every_grading_key_is_actually_cleared_not_merely_warned_about(audit):
    """The lint for the class, rather than for the three instances.

    `_refuse_target_policy` warns for each key in `_GRADING_KEYS` and then
    clears the keys in a separate expression. Those two lists were written
    by hand and independently, so a key added to the tuple warns the
    operator that it was ignored and then applies anyway — a warning that
    states the opposite of what happened, which is worse than silence.

    This reads the refusal's own output: every key the policy names as
    ignored must be falsy on the config it returns.
    """
    from dataclasses import replace
    from pathlib import Path

    from secure_code_audit import config as config_mod
    from secure_code_audit.cli import _GRADING_KEYS, _refuse_target_policy

    tree = Path.cwd()
    loaded = replace(
        config_mod.Config(),
        source_path=tree / "secure-code-agent.json",
        severity_overrides={"B602": "informational"},
        category_overrides={"B602": "policy_docs"},
        loc_for_scoring={"value": 10_000_000, "reason": "generated"},
    )
    assert all(getattr(loaded, key) for key in _GRADING_KEYS), (
        f"this test must set every key in {_GRADING_KEYS} to something truthy, "
        "or it proves nothing about the ones it left empty"
    )

    refused = _refuse_target_policy(loaded, tree)

    still_applied = [key for key in _GRADING_KEYS if getattr(refused, key)]
    assert still_applied == [], (
        f"{still_applied} are named in _GRADING_KEYS, so the operator is warned they "
        "were ignored, and they were still applied. Derive the clearing from the "
        "tuple rather than restating it."
    )


def test_a_config_outside_the_tree_still_honours_the_overrides(audit, tmp_path):
    """An operator's own config, kept outside the audited tree, is trusted.

    That is the arrangement a host uses when auditing someone else's code,
    and the one `test_declared_config_is_live.py` relies on for every key it
    tests. Breaking it would break policy configuration generally.
    """
    outside = tmp_path / "operator-config.json"
    outside.write_text(json.dumps(_DOWNGRADE), encoding="utf-8")

    report = audit(None, extra_argv=("--config", str(outside)))

    severities = {f["rule_id"]: f["severity"] for f in report["findings"]}
    assert severities.get("B602") == "informational", severities
