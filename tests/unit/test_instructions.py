import pytest

from secure_code_audit import instructions


def test_write_new_append_and_refresh_agent_instructions(tmp_path):
    path = instructions.write_for_target("codex", tmp_path)
    first = path.read_text(encoding="utf-8")
    assert "secure-code-agent:standards" in first

    path.write_text("# Repo rules\n\n" + first, encoding="utf-8")
    refreshed = instructions.write_for_target("codex", tmp_path)
    content = refreshed.read_text(encoding="utf-8")

    assert content.startswith("# Repo rules")
    assert content.count("<!-- secure-code-agent:standards -->") == 1


def test_write_for_targets_and_unknown_target(tmp_path):
    written = instructions.write_for_targets(["generic", "claude-code"], tmp_path)
    assert len(written) == 2
    assert "codex" in instructions.known_targets()
    with pytest.raises(ValueError, match="Unknown target"):
        instructions.write_for_target("unknown", tmp_path)
