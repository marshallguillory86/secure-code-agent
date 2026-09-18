"""A project may declare what it does, and be reported rather than scored (D24).

A tool that runs external analyzers imports `subprocess` and spawns them. The
scanner reports that, correctly, on every run forever. Before this there was no
way to say "yes, that is what this is": the instruments were `exclude_patterns`
and `--skip`, which delete the observation from the report, and `.scignore.yaml`,
which states a reason and then expires — an annual ritual re-approving a fact
that has not changed.

The declaration keeps the findings in the report, on their own axis, and off
the score. These hold the three properties that separate it from hiding:
it is declared rather than inferred, a declaration that matches nothing is
named, and the score the tree earns *without* the declarations is disclosed
next to the one it earns with them.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from secure_code_audit import renderers
from secure_code_audit.capabilities import (
    AXIS_PREFIX,
    CAPABILITY_RULES,
    capability_for,
    summarize_declarations,
    unknown_capabilities,
)
from secure_code_audit.cli import main
from secure_code_audit.config import load
from secure_code_audit.findings import Category, Confidence, Finding, Severity
from secure_code_audit.scoring import summarize_axis


def _finding(rule_id: str, path: str = "src/runner.py") -> Finding:
    return Finding(
        rule_id=rule_id,
        scanner="bandit",
        fingerprint=f"fp:{rule_id}:{path}",
        canonical_cwe=None,
        owasp_top10=None,
        asvs_section=None,
        nist_ssdf=None,
        category=Category.CODE_VULNERABILITIES,
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        file_path=Path(path),
        line_start=1,
        line_end=1,
        code_snippet=None,
        message=f"{rule_id} reported",
    )


def _write(tmp_path, raw: str):
    path = tmp_path / "secure-code-agent.json"
    path.write_text(raw, encoding="utf-8")
    return load(path)


# --- the declaration accounts for its own findings -------------------------


def test_a_declared_capability_claims_the_rules_that_are_it():
    """`spawns_processes` accounts for the reports that say a process started."""
    assert capability_for(_finding("B603"), ["spawns_processes"]) == "spawns_processes"
    assert capability_for(_finding("B404"), ["spawns_processes"]) == "spawns_processes"


def test_an_undeclared_capability_claims_nothing():
    """Declaring one capability does not quietly account for another's rules."""
    assert capability_for(_finding("B310"), ["spawns_processes"]) is None
    assert capability_for(_finding("B603"), []) is None


def test_shell_true_is_not_covered_by_declaring_process_spawning():
    """Spawning a process is architecture; handing a string to a shell is a choice.

    B602 is deliberately outside every capability. A project that declares it
    runs subprocesses has not thereby excused `shell=True`, which is the one
    subprocess finding that is a decision rather than a shape.
    """
    assert "B602" not in CAPABILITY_RULES["spawns_processes"]
    assert capability_for(_finding("B602"), list(CAPABILITY_RULES)) is None


# --- a declaration is falsifiable -----------------------------------------


def test_a_declaration_that_matches_nothing_is_reported():
    """A config cannot be padded against findings that have not arrived."""
    report = summarize_declarations(
        {"spawns_processes": "runs analyzers", "fetches_remote_urls": "no it does not"},
        [_finding("B603"), _finding("B404")],
    )

    assert report.accounted["spawns_processes"] == 2
    assert report.unexercised == ("fetches_remote_urls",)


def test_what_a_declaration_accounted_for_is_counted():
    report = summarize_declarations(
        {"spawns_processes": "runs analyzers"}, [_finding("B603"), _finding("B404")]
    )
    assert report.total_accounted == 2


# --- the configuration refuses what it cannot honour ----------------------


def test_a_misspelled_capability_is_refused_not_ignored(tmp_path):
    """A typo would declare nothing, route nothing, and score the findings
    the operator believed were accounted for — silently."""
    with pytest.raises(ValueError, match="unknown capabilities"):
        _write(tmp_path, '{"version": 1, "capabilities": {"spawns_procesess": "typo"}}')


def test_a_declaration_without_a_reason_is_refused(tmp_path):
    """The reason is what a reviewer reads to decide it is still true."""
    with pytest.raises(ValueError, match="non-empty reason"):
        _write(tmp_path, '{"version": 1, "capabilities": {"spawns_processes": "  "}}')


def test_capabilities_must_be_an_object(tmp_path):
    with pytest.raises(ValueError, match="capabilities must be"):
        _write(tmp_path, '{"version": 1, "capabilities": ["spawns_processes"]}')


def test_a_declared_capability_survives_the_unknown_key_sweep(tmp_path):
    """`capabilities` is a key this tool reads, so the strict sweep admits it."""
    cfg = _write(
        tmp_path,
        '{"version": 1, "capabilities": {"spawns_processes": "runs the analyzer pool"}}',
    )
    assert cfg.capabilities == {"spawns_processes": "runs the analyzer pool"}


def test_no_declaration_is_the_default(tmp_path):
    cfg = _write(tmp_path, '{"version": 1}')
    assert cfg.capabilities == {}
    assert unknown_capabilities(cfg.capabilities) == ()


# ---------------------------------------------------------------------------
# D25 — the declared reason reaches the page
# ---------------------------------------------------------------------------


def test_a_declared_axis_carries_the_reason_the_project_stated() -> None:
    """The note is the configured sentence, not a constant the tool wrote.

    0.12.6 routed the declaration and never printed it. A reader got
    `## Declared: spawns_processes`, a count, and no statement of why — the
    disclosure the mechanism rests on, missing from the artifact it rests in.
    """
    axis = summarize_axis(
        AXIS_PREFIX + "spawns_processes",
        [_finding("B404")],
        note="Runs the analyzer pool as subprocesses.",
    )

    assert axis.note == "Runs the analyzer pool as subprocesses."


def test_the_markdown_report_prints_the_declared_reason() -> None:
    """Present in the rendered section, not merely on the object."""
    axis = summarize_axis(
        AXIS_PREFIX + "spawns_processes",
        [_finding("B404")],
        note="Runs the analyzer pool as subprocesses. ADR 006.",
    )

    section = renderers._axis_section(axis)

    assert "Runs the analyzer pool as subprocesses. ADR 006." in section


def test_the_json_report_carries_the_declared_reason() -> None:
    """A consumer reading the machine artifact gets the reason too."""
    axis = summarize_axis(
        AXIS_PREFIX + "spawns_processes",
        [_finding("B404")],
        note="Runs the analyzer pool as subprocesses.",
    )

    blocks = renderers._axes_to_dict([axis])

    assert blocks[renderers._axis_key(AXIS_PREFIX + "spawns_processes")]["note"] == (
        "Runs the analyzer pool as subprocesses."
    )


def test_a_fixed_axis_keeps_the_note_the_tool_holds() -> None:
    """The test tree's sentence is the same for every project, so it stays put.

    Carrying a per-axis note must not silence the axes whose justification the
    tool does own.
    """
    axis = summarize_axis("test tree", [_finding("B404", "tests/test_runner.py")], 100)

    assert "graded on the wrong thing" in renderers._axis_section(axis)


def test_the_reason_survives_the_whole_run_to_the_report(tmp_path: Path) -> None:
    """End to end: config sentence in, rendered sentence out.

    The unit tests above hold the renderer and the axis. This holds the wiring
    between them, which is the half that broke: in 0.12.6 every piece worked
    and nothing carried the reason from `cfg.capabilities` to the axis, so the
    feature was correct and invisible.
    """
    reason = "Runs its analyzer pool as subprocesses, which is the product."
    (tmp_path / "runner.py").write_text(
        "import subprocess\n\n\ndef go():\n    subprocess.run(['ls'], check=False)\n",
        encoding="utf-8",
    )
    config = tmp_path / "secure-code-agent.json"
    config.write_text(
        json.dumps(
            {
                "version": 1,
                "capabilities": {"spawns_processes": reason},
                "gates": {"fail_on_severity": ["critical"]},
            }
        ),
        encoding="utf-8",
    )
    report = tmp_path / "report.md"
    json_report = tmp_path / "report.json"

    main(
        [
            str(tmp_path),
            "--config",
            str(config),
            "--only-scanners",
            "bandit",
            "--output",
            str(report),
            "--json-output",
            str(json_report),
        ]
    )

    payload = json.loads(json_report.read_text(encoding="utf-8"))
    axis = payload["reported_not_scored"]["declared:_spawns_processes"]
    assert axis["count"] >= 1, "the declaration routed nothing; the rest proves nothing"
    assert axis["note"] == reason
    assert reason in report.read_text(encoding="utf-8")
