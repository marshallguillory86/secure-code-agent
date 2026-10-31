"""Contract tests for the falsifier-proof gate."""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.stdout.strip()


def _write(repo: Path, relative: str, content: str) -> None:
    path = repo / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _repository(tmp_path: Path) -> tuple[Path, str]:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "--quiet")
    _git(repo, "config", "user.name", "marshallguillory86")
    _git(repo, "config", "user.email", "152444602+marshallguillory86@users.noreply.github.com")
    _git(repo, "config", "commit.gpgsign", "false")
    _write(repo, "src/demo/__init__.py", "def value():\n    return 1\n")
    _write(
        repo,
        "tests/test_demo.py",
        "from demo import value\n\n\ndef test_base_behaviour():\n    assert value() == 1\n",
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "--quiet", "-m", "base")
    return repo, _git(repo, "rev-parse", "HEAD")


def _commit_head(repo: Path, message: str = "change") -> None:
    _git(repo, "add", ".")
    _git(repo, "commit", "--quiet", "-m", message)


def _tool():
    path = ROOT / "tools/prove_falsifiers.py"
    spec = importlib.util.spec_from_file_location("prove_falsifiers", path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"could not load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(repo: Path, base: str, capsys: pytest.CaptureFixture[str]) -> tuple[int, str]:
    result = _tool().main(["--base", base, "--root", str(repo)])
    return result, capsys.readouterr().out


def test_fix_and_new_test_are_proven(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    repo, base = _repository(tmp_path)
    _write(repo, "src/demo/__init__.py", "def value():\n    return 2\n")
    _write(
        repo,
        "tests/test_demo.py",
        "from demo import value\n\n\ndef test_base_behaviour():\n    assert value() == 1\n\n\ndef test_new_behaviour():\n    assert value() == 2\n",
    )
    _commit_head(repo)

    result, output = _run(repo, base, capsys)

    assert result == 0
    assert "tests/test_demo.py::test_new_behaviour" in output
    assert "proven" in output


def test_passing_new_test_is_rejected(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    repo, base = _repository(tmp_path)
    _write(
        repo,
        "tests/test_new.py",
        "from demo import value\n\n\ndef test_already_true():\n    assert value() == 1\n",
    )
    _commit_head(repo)

    result, output = _run(repo, base, capsys)

    assert result == 1
    assert "tests/test_new.py::test_already_true" in output
    assert "passes without its change" in output


def test_passing_function_added_to_existing_file_is_rejected(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    repo, base = _repository(tmp_path)
    _write(
        repo,
        "tests/test_demo.py",
        "from demo import value\n\n\ndef test_base_behaviour():\n    assert value() == 1\n\n\ndef test_added_to_existing_file():\n    assert value() == 1\n",
    )
    _commit_head(repo)

    result, output = _run(repo, base, capsys)

    assert result == 1
    assert "tests/test_demo.py::test_added_to_existing_file" in output
    assert "passes without its change" in output


def test_unrelated_edit_to_modified_test_file_has_nothing_to_prove(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    repo, base = _repository(tmp_path)
    _write(
        repo,
        "tests/test_demo.py",
        "# unrelated edit\nfrom demo import value\n\n\ndef test_base_behaviour():\n    assert value() == 1\n",
    )
    _commit_head(repo)

    result, output = _run(repo, base, capsys)

    assert result == 0
    assert "nothing to prove" in output


def test_existing_behaviour_marker_exempts_new_test(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    repo, base = _repository(tmp_path)
    _write(
        repo,
        "tests/test_new.py",
        'from demo import value\n\n\ndef test_characterisation():\n    """Covers existing behaviour: baseline contract."""\n    assert value() == 1\n',
    )
    _commit_head(repo)

    result, output = _run(repo, base, capsys)

    assert result == 0
    assert "tests/test_new.py::test_characterisation" in output
    assert "exempt" in output


def test_collection_import_error_is_a_weaker_proof(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    repo, base = _repository(tmp_path)
    _write(
        repo,
        "tests/test_new.py",
        "from demo import new_api\n\n\ndef test_new_api():\n    assert new_api() == 2\n",
    )
    _commit_head(repo)

    result, output = _run(repo, base, capsys)

    assert result == 0
    assert "tests/test_new.py::test_new_api" in output
    assert "import" in output.lower()


def test_scratch_worktree_is_removed_after_run(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    repo, base = _repository(tmp_path)
    _write(repo, "src/demo/__init__.py", "def value():\n    return 2\n")
    _write(
        repo,
        "tests/test_demo.py",
        "from demo import value\n\n\ndef test_base_behaviour():\n    assert value() == 1\n\n\ndef test_new_behaviour():\n    assert value() == 2\n",
    )
    _commit_head(repo)

    result, _ = _run(repo, base, capsys)

    assert result == 0
    worktrees = _git(repo, "worktree", "list", "--porcelain").splitlines()
    assert sum(line.startswith("worktree ") for line in worktrees) == 1
    assert worktrees[0] == f"worktree {repo}"
