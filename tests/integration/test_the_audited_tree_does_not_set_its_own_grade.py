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
