import json

from secure_code_audit.cli import _under_root, main


def _write_config(tmp_path, *, required: bool):
    config = {
        "version": 1,
        "scanners": {
            "trivy": {
                "enabled": True,
                "command": [str(tmp_path / "missing-trivy")],
            }
        },
        "gates": {"require_scanners": ["trivy"] if required else []},
    }
    path = tmp_path / "secure-code-agent.json"
    path.write_text(json.dumps(config), encoding="utf-8")
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
