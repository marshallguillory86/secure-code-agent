"""A disappearing directory must not crash an audit or expose its git data.

The audited tree walker skips ``.git``, does not follow directory symlinks,
and treats a directory that cannot be opened as empty. All tree discovery in
the package is required to use that one walker.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "src" / "secure_code_audit"


def _tree(tmp_path: Path) -> Path:
    root = tmp_path / "tree"
    for rel, text in {
        "src/app.py": "def run():\n    return 1\n",
        "gone/inner.py": "def lost():\n    return 2\n",
        ".git/worktrees/w1/HEAD": "ref: refs/heads/x\n",
        ".git/objects/ab/cdef.py": "def not_source():\n    return 3\n",
    }.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def _vanishing(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    """Make opening a directory named ``name`` behave as if it vanished."""
    real_scandir = os.scandir

    def scandir(path: os.PathLike[str] | str = ".") -> os.ScandirIterator[str]:  # type: ignore[type-var]
        if Path(path).name == name:
            raise FileNotFoundError(2, "No such file or directory", str(path))
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", scandir)


def test_walk_skips_dot_git_and_survives_a_vanishing_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from secure_code_audit._walk import walk

    root = _tree(tmp_path)
    _vanishing(monkeypatch, "gone")

    found = {path.relative_to(root).as_posix() for path in walk(root) if path.is_file()}
    assert found == {"src/app.py"}


def test_walk_matches_a_name_pattern_like_rglob(tmp_path: Path) -> None:
    from secure_code_audit._walk import walk

    root = _tree(tmp_path)

    assert {path.relative_to(root).as_posix() for path in walk(root, "*.py")} == {
        "src/app.py",
        "gone/inner.py",
    }


def test_full_cli_audit_never_opens_a_directory_inside_dot_git(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The full CLI run must avoid git internals even while worktrees vanish."""
    from secure_code_audit.cli import main

    root = _tree(tmp_path)
    (root / ".git" / "secret.py").write_text("password = 'not-a-finding'\n", encoding="utf-8")
    config = tmp_path / "secure-code-agent.json"
    config.write_text(json.dumps({"gates": {}}), encoding="utf-8")

    opened: list[Path] = []
    real_scandir = os.scandir

    def recording_scandir(
        path: os.PathLike[str] | str = ".",
    ) -> os.ScandirIterator[str]:  # type: ignore[type-var]
        opened.append(Path(path))
        if Path(path).name == "worktrees":
            raise FileNotFoundError(2, "No such file or directory", str(path))
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", recording_scandir)

    try:
        exit_code = main(
            [
                str(root),
                "--config",
                str(config),
                "--only-scanners",
                "builtin_rules",
                "--output",
                str(tmp_path / "report.md"),
                "--json-output",
                str(tmp_path / "report.json"),
            ]
        )
    except FileNotFoundError:
        exit_code = None

    assert exit_code == 0
    git = (root / ".git").resolve()
    inside_git = [path for path in opened if path.resolve() == git or git in path.resolve().parents]
    assert inside_git == [], f"the audit opened {len(inside_git)} directories inside .git"


def test_no_module_walks_the_tree_except_through_the_one_walker() -> None:
    offenders = [
        f"{path.relative_to(PACKAGE)}:{number}"
        for path in sorted(PACKAGE.rglob("*.py"))
        if path.name != "_walk.py"
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if re.search(r"\.rglob\(", line) and not line.lstrip().startswith("#")
    ]
    assert offenders == []
