from secure_code_audit import git_tools


def test_find_repo_root(tmp_path):
    repo = tmp_path / "repo"
    child = repo / "src"
    (repo / ".git").mkdir(parents=True)
    child.mkdir()
    assert git_tools.find_repo_root(child) == repo


def test_scope_exclusions_and_loc(tmp_path):
    (tmp_path / "keep.py").write_text("one\n\ntwo\n", encoding="utf-8")
    excluded = tmp_path / "node_modules" / "skip.py"
    excluded.parent.mkdir()
    excluded.write_text("three\n", encoding="utf-8")
    (tmp_path / "Dockerfile.dev").write_text("FROM scratch\n", encoding="utf-8")

    assert git_tools.is_excluded(excluded, tmp_path, ("node_modules/",))
    assert git_tools.in_scope(tmp_path / "keep.py", (".py",))
    assert git_tools.in_scope(tmp_path / "Dockerfile.dev", ("Dockerfile",))
    # loc_under returns (primary, test); with no test patterns everything is
    # primary, so the denominator cannot silently shrink.
    assert git_tools.loc_under(tmp_path, (".py", "Dockerfile"), ("node_modules/",)) == (3, 0, 0)


def test_tracked_files_lists_what_git_tracks(tmp_path):
    """One audited place for every git invocation in this repository.

    `tools/render_docs.py` needs the set of tracked documents, and its first
    cut called `subprocess` itself — which the self-audit immediately flagged
    three ways: B404 for the import, B603 for the call, and B607 for naming
    `git` by a partial path. `maintainability-agent`'s renderer carries the
    same note about its own first cut.

    Resolving it here instead means the subprocess stays in the one module
    already reviewed and suppressed for it, with `_git()` giving an absolute
    path. A docs tool should not be the second place this project shells out.
    """
    import subprocess

    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True, timeout=120)
    (tmp_path / "docs").mkdir()
    (tmp_path / "README.md").write_text("# Readme\n", encoding="utf-8")
    (tmp_path / "docs" / "guide.md").write_text("# Guide\n", encoding="utf-8")
    (tmp_path / "untracked.md").write_text("# Not added\n", encoding="utf-8")
    (tmp_path / "code.py").write_text("x = 1\n", encoding="utf-8")
    subprocess.run(
        ["git", "-C", str(tmp_path), "add", "README.md", "docs/guide.md", "code.py"],
        check=True,
        timeout=120,
    )

    assert set(git_tools.tracked_files(tmp_path, "*.md")) == {"README.md", "docs/guide.md"}


def test_tracked_files_is_empty_outside_a_repository(tmp_path):
    """A caller outside git gets nothing, not a crash.

    The renderer runs from a checkout, but a tarball of the sources is not a
    checkout, and a tool that raised there would be a worse failure than
    rendering no pages.
    """
    assert git_tools.tracked_files(tmp_path, "*.md") == []


def test_tracked_files_accepts_several_patterns(tmp_path):
    """The index links standalone HTML as well as markdown."""
    import subprocess

    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True, timeout=120)
    (tmp_path / "a.md").write_text("# A\n", encoding="utf-8")
    (tmp_path / "b.html").write_text("<p>b</p>\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "a.md", "b.html"], check=True, timeout=120)

    assert set(git_tools.tracked_files(tmp_path, "*.md", "*.html")) == {"a.md", "b.html"}
