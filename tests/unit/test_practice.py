"""Security practice level, read from configuration and CI — never from source.

MA's rubric, its level definitions and its `MAX_WITHOUT_CI` cap, applied to
security. The separation is the point: a scan says the code is clean today; it
cannot say whether anything stops tomorrow's merge from committing a key.
"""

from __future__ import annotations

from pathlib import Path

from secure_code_audit import practice


def _repo(tmp_path: Path, files: dict[str, str]) -> Path:
    for name, body in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    return tmp_path


def test_an_empty_repository_is_level_one(tmp_path):
    assessed = practice.assess(tmp_path)

    assert assessed.level == 1
    assert "nothing detectable" in assessed.summary
    assert assessed.signals == ()


def test_configuration_without_ci_is_level_two(tmp_path):
    """Intent is not enforcement — MA's MAX_WITHOUT_CI, same reasoning.

    A repository can hold every scanner config ever written and still merge
    anything. The gap between having a config and running it is the single most
    useful thing this measurement reports.
    """
    root = _repo(tmp_path, {"secure-code-agent.json": '{"version": 1}'})

    assessed = practice.assess(root)

    assert assessed.level == 2
    assert any(s.path == "secure-code-agent.json" for s in assessed.signals)


def test_a_gate_declared_but_never_run_is_still_capped_at_two(tmp_path):
    """The cap has to survive a config that *looks* strict.

    A `fail_on_severity` in a file no CI executes is a preference written down.
    Without the cap this would read level 4 and claim enforcement that does not
    exist.
    """
    root = _repo(
        tmp_path,
        {"secure-code-agent.json": '{"gates": {"fail_on_severity": ["critical"]}}'},
    )

    assessed = practice.assess(root)

    assert assessed.level == practice.MAX_WITHOUT_CI
    assert assessed.caps, "a held-down level must say what held it"
    assert "capped" in assessed.caps[0]


def test_ci_that_runs_a_scanner_is_level_three(tmp_path):
    root = _repo(
        tmp_path,
        {
            "secure-code-agent.json": "{}",
            ".github/workflows/ci.yml": "jobs:\n  s:\n    steps:\n      - run: bandit -r .\n",
        },
    )

    assessed = practice.assess(root)

    assert assessed.level == 3
    assert any("CI runs bandit" in s.signal for s in assessed.signals)


def test_ci_with_a_threshold_is_level_four(tmp_path):
    root = _repo(
        tmp_path,
        {
            "secure-code-agent.json": "{}",
            ".github/workflows/ci.yml": (
                "jobs:\n  s:\n    steps:\n      - run: secure-code-agent . --fail-on-gate\n"
            ),
        },
    )

    assessed = practice.assess(root)

    assert assessed.level == 4
    assert any("--fail-on-gate" in s.signal for s in assessed.signals)


def test_gates_plus_discipline_is_level_five(tmp_path):
    root = _repo(
        tmp_path,
        {
            "secure-code-agent.json": "{}",
            ".github/workflows/ci.yml": (
                "jobs:\n  s:\n    steps:\n      - run: secure-code-agent . --fail-on-gate\n"
            ),
            "SECURITY.md": "# Reporting\n",
        },
    )

    assessed = practice.assess(root)

    assert assessed.level == 5


def test_a_suppression_that_expires_counts_as_discipline(tmp_path):
    """A suppression with no expiry is a permanent exception wearing a
    temporary name; the date is what makes it reviewable."""
    root = _repo(
        tmp_path,
        {
            "secure-code-agent.json": "{}",
            ".github/workflows/ci.yml": (
                "jobs:\n  s:\n    steps:\n      - run: secure-code-agent . --fail-on-gate\n"
            ),
            ".scignore.yaml": '- rule_id: B404\n  reason: "x"\n  expires: "2027-01-01"\n',
        },
    )

    assessed = practice.assess(root)

    assert assessed.level == 5
    assert any("expiry" in s.signal for s in assessed.signals)


def test_ci_without_any_security_job_is_capped(tmp_path):
    """CI that builds and tests but never scans is not security enforcement."""
    root = _repo(
        tmp_path,
        {
            "secure-code-agent.json": "{}",
            ".github/workflows/ci.yml": "jobs:\n  t:\n    steps:\n      - run: pytest\n",
        },
    )

    assessed = practice.assess(root)

    # Nothing was capped here — the level is 2 on its own merits, because a
    # config with no threshold in it claims nothing more. What must be true is
    # that no security enforcement is claimed.
    assert assessed.level == practice.MAX_WITHOUT_CI
    assert not any("CI runs" in s.signal for s in assessed.signals)


def test_a_non_github_ci_host_is_recognised(tmp_path):
    """Recognising only GitHub Actions would score every GitLab shop at 2 for
    choosing a different host — a statement about this tool, not about them."""
    root = _repo(
        tmp_path,
        {
            "secure-code-agent.json": "{}",
            ".gitlab-ci.yml": "scan:\n  script:\n    - semgrep --config auto\n",
        },
    )

    assert practice.assess(root).level == 3


def test_every_signal_names_the_file_that_proves_it(tmp_path):
    """A maturity level a reader cannot check is a grade with no marking
    scheme, and this one is a judgment made from the outside."""
    root = _repo(
        tmp_path,
        {
            "secure-code-agent.json": "{}",
            ".github/workflows/ci.yml": "jobs:\n  s:\n    steps:\n      - run: gitleaks detect\n",
            "SECURITY.md": "# x\n",
        },
    )

    assessed = practice.assess(root)

    assert assessed.signals
    for signal in assessed.signals:
        assert signal.path
        assert (root / signal.path).exists(), signal.path


def test_source_code_is_never_read(tmp_path):
    """The axis separation, asserted.

    A vulnerable source file must not move the practice level by one point —
    that is code condition, and it is the other axis.
    """
    clean = _repo(tmp_path / "clean", {"secure-code-agent.json": "{}"})
    dirty = _repo(
        tmp_path / "dirty",
        {
            "secure-code-agent.json": "{}",
            "app.py": 'import os\nos.system("rm -rf /")\nPASSWORD = "hunter2"\n',
        },
    )

    assert practice.assess(clean).level == practice.assess(dirty).level
