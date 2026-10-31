"""Release workflows must publish only a versioned commit from main."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
TIMEOUT = 60


def _run(
    command: list[str],
    *,
    cwd: Path | None = None,
    check: bool = True,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=check,
        timeout=TIMEOUT,
    )


def _git(repo: Path, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return _run(["git", "-C", str(repo), *arguments], check=check)


def _workflow(path: str) -> dict:
    workflow = yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))
    if True in workflow and "on" not in workflow:
        workflow["on"] = workflow.pop(True)
    return workflow


def _step(workflow: dict, job_name: str, step_name: str) -> dict:
    return next(
        step for step in workflow["jobs"][job_name]["steps"] if step.get("name") == step_name
    )


def _configure_repository(repo: Path) -> None:
    _run(["git", "init", "-q", "-b", "main", str(repo)])
    _git(repo, "config", "user.email", "152444602+marshallguillory86@users.noreply.github.com")
    _git(repo, "config", "user.name", "marshallguillory86")
    _git(repo, "config", "commit.gpgsign", "false")
    _git(repo, "config", "tag.gpgsign", "false")
    # A machine-wide pre-push hook may require every pushed repository to
    # declare a local pipeline; this throwaway one declares a trivial one.
    (repo / ".local-pipeline").write_text("true\n", encoding="utf-8")


def _create_release_fixture(tmp_path: Path, *, origin_has_tag: bool) -> Path:
    repo = tmp_path / ("tagged" if origin_has_tag else "untagged")
    repo.mkdir()
    _configure_repository(repo)
    package = repo / "src" / "secure_code_audit"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text('__version__ = "9.9.9"\n', encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "initial")

    origin = tmp_path / ("tagged-origin.git" if origin_has_tag else "untagged-origin.git")
    _run(["git", "init", "--bare", "-q", str(origin)])
    _git(repo, "remote", "add", "origin", str(origin))
    _git(repo, "push", "-q", "origin", "main")
    if origin_has_tag:
        _git(repo, "tag", "v9.9.9")
        _git(repo, "push", "-q", "origin", "v9.9.9")
    return repo


def _run_decision(step: dict, repo: Path, output: Path) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["GITHUB_OUTPUT"] = str(output)
    return _run(["bash", "-c", step["run"]], cwd=repo, env=environment, check=False)


def test_cut_release_dispatches_the_release_and_cuts_no_tag():
    workflow_path = ROOT / ".github" / "workflows" / "cut-release.yml"
    assert workflow_path.is_file()
    workflow_text = workflow_path.read_text(encoding="utf-8")
    workflow = _workflow(".github/workflows/cut-release.yml")
    triggers = workflow["on"]

    assert set(triggers) == {"push"}
    assert triggers["push"] == {"branches": ["main"]}
    assert "pull_request" not in triggers
    assert "tags" not in triggers["push"]
    assert "pytest" not in workflow_text.lower()

    assert len(workflow["jobs"]) == 1
    job = next(iter(workflow["jobs"].values()))
    assert job["permissions"] == {"contents": "read", "actions": "write"}
    scripts = "\n".join(step.get("run", "") for step in job["steps"])
    assert "__version__" in scripts
    assert "gh workflow run release.yaml --ref main" in scripts
    assert "git tag" not in workflow_text
    assert "git push" not in workflow_text
    assert "pytest" not in workflow_text.lower()


def test_cut_release_decision_reports_remote_tag_state(tmp_path):
    workflow = _workflow(".github/workflows/cut-release.yml")
    decision = _step(
        workflow, next(iter(workflow["jobs"])), "Decide whether this version is released"
    )
    assert decision.get("shell") == "bash"
    assert "tag=v" in decision["run"]
    assert "release=true" in decision["run"]
    assert "release=false" in decision["run"]
    assert '"$GITHUB_OUTPUT"' in decision["run"]

    tagged_repo = _create_release_fixture(tmp_path, origin_has_tag=True)
    tagged_output = tmp_path / "tagged-output"
    before_local_tags = _git(tagged_repo, "tag", "--list").stdout
    before_remote_tags = _git(tagged_repo, "ls-remote", "--tags", "origin").stdout
    result = _run_decision(decision, tagged_repo, tagged_output)
    assert result.returncode == 0, result.stderr
    assert "release=false" in tagged_output.read_text(encoding="utf-8")
    assert _git(tagged_repo, "tag", "--list").stdout == before_local_tags
    assert _git(tagged_repo, "ls-remote", "--tags", "origin").stdout == before_remote_tags

    untagged_repo = _create_release_fixture(tmp_path, origin_has_tag=False)
    untagged_output = tmp_path / "untagged-output"
    result = _run_decision(decision, untagged_repo, untagged_output)
    assert result.returncode == 0, result.stderr
    assert "release=true" in untagged_output.read_text(encoding="utf-8")


def _create_main_history(tmp_path: Path) -> tuple[Path, str, str]:
    repo = tmp_path / "history"
    repo.mkdir()
    _configure_repository(repo)
    file_path = repo / "history.txt"
    file_path.write_text("A\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "A")
    file_path.write_text("A\nB\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "B")
    commit_b = _git(repo, "rev-parse", "HEAD").stdout.strip()

    origin = tmp_path / "history-origin.git"
    _run(["git", "init", "--bare", "-q", str(origin)])
    _git(repo, "remote", "add", "origin", str(origin))
    _git(repo, "push", "-q", "origin", "main")
    _git(repo, "checkout", "-q", "-b", "side")
    file_path.write_text("A\nB\nC\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "C")
    commit_c = _git(repo, "rev-parse", "HEAD").stdout.strip()
    return repo, commit_b, commit_c


def test_release_workflow_guards_the_build_to_a_tagged_commit_on_main(tmp_path):
    workflow = _workflow(".github/workflows/release.yaml")
    triggers = workflow["on"]
    assert "workflow_dispatch" in triggers
    assert triggers["push"] == {"tags": ["v*"]}
    assert "branches" not in triggers["push"]

    build_steps = workflow["jobs"]["build"]["steps"]
    checkout_index = next(
        index
        for index, step in enumerate(build_steps)
        if step.get("uses", "").startswith("actions/checkout@")
    )
    assert build_steps[checkout_index]["with"]["fetch-depth"] == 0
    guard = build_steps[checkout_index + 1]
    assert guard["name"] == "The tagged commit is on main"

    repo, commit_b, commit_c = _create_main_history(tmp_path)
    environment = os.environ.copy()
    environment["GITHUB_SHA"] = commit_b
    result = _run(["bash", "-c", guard["run"]], cwd=repo, env=environment, check=False)
    assert result.returncode == 0, result.stderr

    environment["GITHUB_SHA"] = commit_c
    result = _run(["bash", "-c", guard["run"]], cwd=repo, env=environment, check=False)
    assert result.returncode != 0


def test_the_release_version_step_refuses_a_released_version(tmp_path):
    workflow = _workflow(".github/workflows/release.yaml")
    build = workflow["jobs"]["build"]
    version_step = _step(workflow, "build", "The version is new or matches its tag")

    assert build["outputs"]["version"] == "${{ steps.version.outputs.version }}"

    untagged_repo = _create_release_fixture(tmp_path, origin_has_tag=False)
    output = tmp_path / "version-output"
    environment = os.environ.copy()
    environment.update(
        {
            "GITHUB_OUTPUT": str(output),
            "GITHUB_REF_TYPE": "branch",
            "GITHUB_REF_NAME": "main",
        }
    )
    result = _run(
        ["bash", "-c", version_step["run"]],
        cwd=untagged_repo,
        env=environment,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "version=9.9.9" in output.read_text(encoding="utf-8")

    tagged_repo = _create_release_fixture(tmp_path, origin_has_tag=True)
    environment["GITHUB_OUTPUT"] = str(tmp_path / "existing-version-output")
    result = _run(
        ["bash", "-c", version_step["run"]],
        cwd=tagged_repo,
        env=environment,
        check=False,
    )
    assert result.returncode != 0

    environment.update(
        {
            "GITHUB_REF_TYPE": "tag",
            "GITHUB_REF_NAME": "v9.9.9",
            "GITHUB_OUTPUT": str(tmp_path / "tag-version-output"),
        }
    )
    result = _run(
        ["bash", "-c", version_step["run"]],
        cwd=untagged_repo,
        env=environment,
        check=False,
    )
    assert result.returncode == 0, result.stderr

    environment["GITHUB_REF_NAME"] = "v1.0.0"
    result = _run(
        ["bash", "-c", version_step["run"]],
        cwd=untagged_repo,
        env=environment,
        check=False,
    )
    assert result.returncode != 0


def test_release_publication_jobs_use_trusted_publishing_and_ordering():
    workflow = _workflow(".github/workflows/release.yaml")
    publish_pypi = workflow["jobs"]["publish-pypi"]
    publish_github = workflow["jobs"]["publish-github"]
    tag = workflow["jobs"]["tag"]

    assert publish_pypi["environment"]["name"] == "pypi"
    assert publish_pypi["permissions"] == {"id-token": "write"}
    tag_needs = tag["needs"]
    assert "publish-pypi" in (tag_needs if isinstance(tag_needs, list) else [tag_needs])
    assert tag["permissions"] == {"contents": "write"}
    tag_scripts = "\n".join(step.get("run", "") for step in tag["steps"])
    assert "git tag" in tag_scripts
    assert "git push" in tag_scripts
    assert "GITHUB_REF_TYPE" in tag_scripts
    needs = publish_github["needs"]
    assert "publish-pypi" in (needs if isinstance(needs, list) else [needs])
    assert "tag" in (needs if isinstance(needs, list) else [needs])
