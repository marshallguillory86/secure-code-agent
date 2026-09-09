import json
from pathlib import Path

from secure_code_audit import config as config_mod
from secure_code_audit.cli import (
    _parse_sarif_import,
    _under_root,
    main,
)
from secure_code_audit.scanners.bandit_scanner import BanditScanner
from secure_code_audit.scanners.pip_audit_scanner import PipAuditScanner


def _write_config(tmp_path, *, required: bool):
    config = {
        "version": 1,
        "scanners": {
            "trivy": {
                "enabled": True,
                "command": [str(tmp_path / "missing-trivy")],
            }
        },
        # When trivy is not required we still configure a real gate, so the
        # test proves the gate ran and chose not to trip — rather than
        # proving nothing was gated at all.
        "gates": (
            {"require_scanners": ["trivy"]} if required else {"fail_on_severity": ["critical"]}
        ),
    }
    path = tmp_path / "secure-code-agent.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    # Trivy is only required where it has something to read. Without this the
    # tree is a lone JSON file and the applicability filter — correctly —
    # drops trivy from the required set.
    (tmp_path / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    return path


def test_cli_fails_when_required_scanner_is_unavailable(tmp_path):
    config = _write_config(tmp_path, required=True)
    report = tmp_path / "report.md"
    json_report = tmp_path / "report.json"

    exit_code = main(
        [
            str(tmp_path),
            "--config",
            str(config),
            "--only-scanners",
            "trivy",
            "--fail-on-gate",
            "--output",
            str(report),
            "--json-output",
            str(json_report),
        ]
    )

    payload = json.loads(json_report.read_text(encoding="utf-8"))
    assert exit_code == 1
    assert payload["gate"]["passed"] is False
    assert payload["coverage"]["status"] == "failed"
    assert payload["coverage"]["scanners"][0]["outcome"] == "unavailable"


def test_cli_rejects_explicit_missing_config_instead_of_disabling_gates(tmp_path, capsys):
    exit_code = main(
        [
            str(tmp_path),
            "--config",
            str(tmp_path / "typo-config.json"),
            "--fail-on-gate",
        ]
    )

    assert exit_code == 2
    assert "configuration file does not exist" in capsys.readouterr().err


def test_cli_marks_optional_unavailable_scanner_partial_without_failing(tmp_path):
    config = _write_config(tmp_path, required=False)

    exit_code = main(
        [
            str(tmp_path),
            "--config",
            str(config),
            "--only-scanners",
            "trivy",
            "--fail-on-gate",
            "--output",
            str(tmp_path / "report.md"),
        ]
    )

    assert exit_code == 0


def test_cli_rejects_multiple_roots_instead_of_ignoring_them(tmp_path):
    assert main([str(tmp_path / "one"), str(tmp_path / "two")]) == 2


def test_repository_policy_paths_resolve_from_scan_root(tmp_path):
    assert (
        _under_root(tmp_path, ".policy/ignore.yaml") == (tmp_path / ".policy/ignore.yaml").resolve()
    )


def test_pip_audit_scope_discloses_bounded_inputs_and_flags():
    """Scope is declared by the adapter, not inferred from its name.

    The orchestrator used to carry `if name != "pip_audit": return None`,
    because there was nowhere on an adapter to say what it covered
    (architecture.md §2). Asking the adapter is the fix.
    """
    scanner_config = config_mod.ScannerConfig(
        mode="requirements",
        inputs=["requirements-audit.txt"],
        extra_args=["--no-deps"],
    )

    assert BanditScanner().scope(scanner_config) is None
    assert PipAuditScanner().scope(scanner_config) == (
        "mode=requirements; inputs=requirements-audit.txt; extra_args=--no-deps"
    )


def test_preflight_fails_before_auditing_when_a_required_scanner_is_missing(tmp_path, capsys):
    config = _write_config(tmp_path, required=True)

    exit_code = main([str(tmp_path), "--config", str(config), "--preflight"])
    out = capsys.readouterr().out

    assert exit_code == 1
    assert "required scanners unavailable: trivy" in out
    assert not (tmp_path / "secure-code-report.md").exists()


def test_preflight_json_names_the_remedy_without_installing_anything(tmp_path, capsys):
    config = _write_config(tmp_path, required=True)

    exit_code = main([str(tmp_path), "--config", str(config), "--preflight", "--json"])
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 1
    assert payload["ready"] is False
    assert payload["required_unresolved"] == ["trivy"]
    row = next(r for r in payload["scanners"] if r["scanner"] == "trivy")
    assert "brew install trivy" in row["remedy"]
    assert "--sarif-import" in row["remedy"]


def test_preflight_reports_a_required_scanner_that_is_not_even_enabled(tmp_path, capsys):
    (tmp_path / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    config = tmp_path / "secure-code-agent.json"
    config.write_text(
        json.dumps(
            {
                "scanners": {"trivy": {"enabled": False}},
                "gates": {"require_scanners": ["trivy"]},
            }
        ),
        encoding="utf-8",
    )

    exit_code = main([str(tmp_path), "--config", str(config), "--preflight"])

    assert exit_code == 1
    assert "not enabled in this configuration" in capsys.readouterr().out


def test_imported_sarif_satisfies_a_required_scanner_the_host_cannot_install(tmp_path):
    config = tmp_path / "secure-code-agent.json"
    config.write_text(
        json.dumps(
            {
                "scanners": {"builtin_rules": {"enabled": True}},
                "gates": {"require_scanners": ["trivy"]},
            }
        ),
        encoding="utf-8",
    )
    imported = tmp_path / "trivy.sarif"
    imported.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [{"tool": {"driver": {"name": "Trivy", "rules": []}}, "results": []}],
            }
        ),
        encoding="utf-8",
    )
    out = tmp_path / "report.json"

    exit_code = main(
        [
            str(tmp_path),
            "--config",
            str(config),
            "--fail-on-gate",
            "--only-scanners",
            "builtin_rules",
            "--sarif-import",
            str(imported),
            "--json-output",
            str(out),
        ]
    )
    payload = json.loads(out.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert payload["coverage"]["status"] == "complete"
    trivy = next(s for s in payload["coverage"]["scanners"] if s["name"] == "trivy")
    assert trivy["scope"] == "sarif-import:trivy.sarif"


def test_unreadable_sarif_import_fails_the_gate_instead_of_ingesting_nothing(tmp_path):
    config = tmp_path / "secure-code-agent.json"
    config.write_text(
        json.dumps(
            {
                "scanners": {"builtin_rules": {"enabled": True}},
                "gates": {"require_scanners": ["builtin_rules"]},
            }
        ),
        encoding="utf-8",
    )

    exit_code = main(
        [
            str(tmp_path),
            "--config",
            str(config),
            "--fail-on-gate",
            "--sarif-import",
            str(tmp_path / "never-written.sarif"),
        ]
    )

    assert exit_code == 1


def test_sarif_import_name_prefix_is_split_from_paths_that_contain_equals(tmp_path):
    assert _parse_sarif_import("trivy=out.sarif") == ("trivy", Path("out.sarif"))
    assert _parse_sarif_import("./a=b/out.sarif") == (None, Path("./a=b/out.sarif"))
    assert _parse_sarif_import("out.sarif") == (None, Path("out.sarif"))


def _vulnerable_repo(tmp_path):
    """A target the built-in rules will flag HIGH (CWE-78)."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "vuln.py").write_text(
        "import subprocess\n\n\ndef run(user_input):\n    subprocess.run(user_input, shell=True)\n",
        encoding="utf-8",
    )
    return tmp_path


def test_high_finding_cannot_pass_the_gate_when_no_gate_is_configured(tmp_path, capsys):
    # Regression for the false green: the audit correctly found a HIGH CWE-78,
    # scored it 0.00/F, and still exited 0 because every gate was absent.
    target = _vulnerable_repo(tmp_path)
    config = tmp_path / "secure-code-agent.json"
    config.write_text(json.dumps({"gates": {}}), encoding="utf-8")

    exit_code = main([str(target), "--config", str(config), "--fail-on-gate"])

    assert exit_code == 2
    assert "no gate is configured" in capsys.readouterr().err


def test_inert_gate_keys_do_not_satisfy_fail_on_gate(tmp_path, capsys):
    target = _vulnerable_repo(tmp_path)
    config = tmp_path / "secure-code-agent.json"
    config.write_text(
        json.dumps({"gates": {"fail_on_severity": [], "fail_on_new": False, "min_score": 0}}),
        encoding="utf-8",
    )

    exit_code = main([str(target), "--config", str(config), "--fail-on-gate"])

    assert exit_code == 2
    assert "no gate is configured" in capsys.readouterr().err


def test_one_configured_gate_is_enough_to_allow_fail_on_gate(tmp_path):
    target = _vulnerable_repo(tmp_path)
    config = tmp_path / "secure-code-agent.json"
    config.write_text(
        json.dumps({"gates": {"fail_on_severity": ["high", "critical"]}}), encoding="utf-8"
    )

    # Not a usage error (2) — the gate runs and trips on the HIGH finding (1).
    assert main([str(target), "--config", str(config), "--fail-on-gate"]) == 1


def test_report_only_audits_still_run_without_any_gate(tmp_path):
    target = _vulnerable_repo(tmp_path)
    config = tmp_path / "secure-code-agent.json"
    config.write_text(json.dumps({"gates": {}}), encoding="utf-8")

    assert main([str(target), "--config", str(config)]) == 0


def test_removing_a_scanner_cannot_buy_a_better_grade(tmp_path):
    # P3, borrowed from maintainability-agent: no input whose removal raises
    # the graded field. The score is a rate over findings, so disabling
    # scanners took this same tree from 0.00/F to 5.00/A+ — the best possible
    # letter, bought by looking less hard.
    target = _vulnerable_repo(tmp_path)

    def run(config_payload, out_name):
        config = tmp_path / f"{out_name}.json"
        config.write_text(json.dumps(config_payload), encoding="utf-8")
        out = tmp_path / f"{out_name}.out.json"
        # Pinned to one scanner so the assertion cannot depend on which other
        # scanners happen to be installed. Without this the test passed locally
        # (no bandit) and failed in CI (bandit finds the same shell=True), which
        # is the test being environment-dependent, not the fix being wrong.
        main(
            [
                str(target),
                "--config",
                str(config),
                "--only-scanners",
                "builtin_rules",
                "--json-output",
                str(out),
            ]
        )
        return json.loads(out.read_text(encoding="utf-8"))["score"]

    looked = run(
        {"scanners": {"builtin_rules": {"enabled": True}}, "gates": {"min_score": 4.0}}, "looked"
    )
    did_not_look = run(
        {"scanners": {"builtin_rules": {"enabled": False}}, "gates": {"min_score": 4.0}}, "blind"
    )

    # The estimate still rises — that is arithmetic over what was found.
    assert did_not_look["overall"] > looked["overall"]
    # The *grade* does not, because neither run declared a scanner set.
    assert looked["verified_grade"] is None
    assert did_not_look["verified_grade"] is None
    assert "require_scanners" in " ".join(did_not_look["evidence_reasons"])


def test_a_grade_is_issued_only_when_a_declared_scanner_set_actually_ran(tmp_path):
    target = _vulnerable_repo(tmp_path)
    config = tmp_path / "secure-code-agent.json"
    config.write_text(
        json.dumps(
            {
                "scanners": {"builtin_rules": {"enabled": True}},
                "gates": {"require_scanners": ["builtin_rules"], "min_score": 4.0},
            }
        ),
        encoding="utf-8",
    )
    out = tmp_path / "report.json"

    main(
        [
            str(target),
            "--config",
            str(config),
            "--only-scanners",
            "builtin_rules",
            "--json-output",
            str(out),
        ]
    )
    payload = json.loads(out.read_text(encoding="utf-8"))["score"]

    assert payload["verified_grade"] == payload["letter"]
    assert payload["evidence_status"] == "complete"
    assert payload["evidence_reasons"] == []


def test_the_default_config_belongs_to_the_target_not_the_shell(tmp_path, monkeypatch):
    """§7: auditing another project used to apply *this* project's policy.

    `config_mod.load` was called before the target was resolved, so the default
    `secure-code-agent.json` came from the shell's working directory. Running
    the audit from a repository with strict gates against an unrelated tree
    silently enforced the wrong policy — and, read the other way, a tree with
    its own config was audited without it.
    """
    caller = tmp_path / "caller"
    caller.mkdir()
    (caller / "secure-code-agent.json").write_text(
        json.dumps({"gates": {"require_scanners": ["trivy"]}}), encoding="utf-8"
    )
    target = _vulnerable_repo(tmp_path / "target")
    (target / "secure-code-agent.json").write_text(
        json.dumps({"gates": {"fail_on_severity": ["critical"]}}), encoding="utf-8"
    )
    out = tmp_path / "report.json"

    monkeypatch.chdir(caller)
    main([str(target), "--only-scanners", "builtin_rules", "--json-output", str(out)])
    payload = json.loads(out.read_text(encoding="utf-8"))

    # The target's own policy, not the caller's.
    assert payload["coverage"]["required"] == []
    assert "trivy" not in json.dumps(payload["coverage"])
