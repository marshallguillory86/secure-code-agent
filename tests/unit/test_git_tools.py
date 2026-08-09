from subprocess import CalledProcessError, CompletedProcess

from secure_code_audit import git_tools


def test_find_repo_root_and_changed_files(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    child = repo / "src"
    (repo / ".git").mkdir(parents=True)
    child.mkdir()
    monkeypatch.setattr(
        git_tools.subprocess,
        "run",
        lambda *args, **kwargs: CompletedProcess(
            args=[], returncode=0, stdout="a.py\ndocs/readme.md\n"
        ),
    )

    assert git_tools.find_repo_root(child) == repo
    assert git_tools.changed_files(repo, "main...HEAD") == [repo / "a.py", repo / "docs/readme.md"]


def test_changed_files_failure_is_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(
        git_tools.subprocess,
        "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(CalledProcessError(1, "git")),
    )
    assert git_tools.changed_files(tmp_path, "bad") == []


def test_scope_exclusions_and_loc(tmp_path):
    (tmp_path / "keep.py").write_text("one\n\ntwo\n", encoding="utf-8")
    excluded = tmp_path / "node_modules" / "skip.py"
    excluded.parent.mkdir()
    excluded.write_text("three\n", encoding="utf-8")
    (tmp_path / "Dockerfile.dev").write_text("FROM scratch\n", encoding="utf-8")

    assert git_tools.is_excluded(excluded, tmp_path, ("node_modules/",))
    assert git_tools.in_scope(tmp_path / "keep.py", (".py",))
    assert git_tools.in_scope(tmp_path / "Dockerfile.dev", ("Dockerfile",))
    assert git_tools.loc_under(tmp_path, (".py", "Dockerfile"), ("node_modules/",)) == 3
