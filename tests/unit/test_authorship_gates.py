"""Executable checks for the repository authorship controls."""

from __future__ import annotations

import os
import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "authorship.yml"
TOOL = ROOT / "tools" / "check_private_names.py"
COMMIT_IDENTITY = "152444602+marshallguillory86@users.noreply.github.com"
STEP_NAMES = {
    "Each commit carries the repository's commit identity",
    "Each commit is signed",
    "Commit messages name only the commit identity",
    "No private repository's name anywhere in the tree",
}


def _git(
    repo: Path, *args: str, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def _git_output(repo: Path, *args: str, env: dict[str, str] | None = None) -> str:
    result = _git(repo, *args, env=env)
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def _step_scripts() -> dict[str, str]:
    document = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    jobs = document["jobs"]
    job = next(iter(jobs.values()))
    scripts = {
        step["name"]: step["run"] for step in job["steps"] if "name" in step and "run" in step
    }
    assert scripts.keys() == STEP_NAMES
    return scripts


def _run_gate(
    repo: Path, name: str, *, private_names: str = "example-private-name"
) -> subprocess.CompletedProcess[str]:
    script = _step_scripts()[name].replace("tools/check_private_names.py", str(TOOL))
    return subprocess.run(
        ["bash", "-c", script],
        cwd=repo,
        env={**os.environ, "PRIVATE_NAMES": private_names},
        text=True,
        capture_output=True,
        check=False,
    )


@pytest.fixture
def signed_repo(tmp_path: Path) -> tuple[Path, Callable[..., str]]:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git_output(repo, "init", "--initial-branch=main")
    _git_output(repo, "config", "user.name", "Repository User")
    _git_output(repo, "config", "user.email", COMMIT_IDENTITY)
    key = tmp_path / "signing_key"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
        check=True,
        capture_output=True,
        text=True,
    )
    _git_output(repo, "config", "gpg.format", "ssh")
    _git_output(repo, "config", "user.signingkey", str(key))
    (repo / ".github").mkdir()
    public_key = key.with_suffix(".pub").read_text(encoding="utf-8").strip()
    (repo / ".github" / "allowed_signers").write_text(
        f"{COMMIT_IDENTITY} {public_key}\n", encoding="utf-8"
    )
    (repo / "base").write_text("base\n", encoding="utf-8")
    _git_output(repo, "add", ".")
    _git_output(repo, "commit", "-m", "base")
    _git_output(repo, "update-ref", "refs/remotes/origin/main", "HEAD")

    counter = 0

    def commit(
        *,
        signed: bool = True,
        author: str = COMMIT_IDENTITY,
        committer: str = COMMIT_IDENTITY,
        message: str | None = None,
        content: str = "change\n",
    ) -> str:
        nonlocal counter
        counter += 1
        (repo / f"change-{counter}").write_text(content, encoding="utf-8")
        _git_output(repo, "add", ".")
        result = _git(
            repo,
            "-c",
            f"user.email={committer}",
            "-c",
            "user.name=Repository User",
            "commit",
            "-S" if signed else "--no-gpg-sign",
            "--author",
            f"Repository User <{author}>",
            "-m",
            message or f"change {counter}",
            env={**os.environ, "GIT_IDENTITY_OVERRIDE": "1"}
            if committer != COMMIT_IDENTITY
            else None,
        )
        assert result.returncode == 0, result.stderr
        return _git_output(repo, "rev-parse", "HEAD")

    return repo, commit


def test_workflow_has_the_four_required_pull_request_steps() -> None:
    document = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    trigger = document.get("on", document.get(True))
    assert trigger == {"pull_request": None}
    assert len(document["jobs"]) == 1
    job = next(iter(document["jobs"].values()))
    assert job["name"] == "Commit identity and signatures"
    assert job["steps"][0]["with"]["ref"] == "${{ github.event.pull_request.head.sha }}"
    assert job["steps"][0]["with"]["fetch-depth"] == 0
    text = "\n".join(step.get("run", "") for step in job["steps"])
    assert COMMIT_IDENTITY in text
    assert "git config gpg.ssh.allowedSignersFile .github/allowed_signers" in text
    assert "grep -o -E" in text and 'grep -v -x -F "$allowed"' in text
    assert "python3 tools/check_private_names.py --no-default-file" in text
    assert "PRIVATE_NAMES: ${{ secrets.PRIVATE_NAMES }}" in yaml.safe_dump(job)


def test_signed_commit_passes_each_gate(signed_repo: tuple[Path, Callable[..., str]]) -> None:
    repo, commit = signed_repo
    commit()
    for name in STEP_NAMES:
        result = _run_gate(repo, name)
        assert result.returncode == 0, f"{name}: {result.stdout}\n{result.stderr}"


def test_empty_range_fails_each_gate(signed_repo: tuple[Path, Callable[..., str]]) -> None:
    repo, _commit = signed_repo
    for name in STEP_NAMES:
        result = _run_gate(repo, name)
        assert result.returncode == 1, name
        assert "this check proved nothing" in result.stdout


def test_wrong_committer_fails_identity_gate(
    signed_repo: tuple[Path, Callable[..., str]],
) -> None:
    repo, commit = signed_repo
    commit(committer="wrong@example.com")
    result = _run_gate(repo, "Each commit carries the repository's commit identity")
    assert result.returncode == 1
    assert "committer: wrong@example.com" in result.stdout


def test_unsigned_commit_fails_signature_gate(
    signed_repo: tuple[Path, Callable[..., str]],
) -> None:
    repo, commit = signed_repo
    commit(signed=False)
    result = _run_gate(repo, "Each commit is signed")
    assert result.returncode == 1
    assert "unsigned" in result.stdout


def test_message_address_other_than_identity_fails(
    signed_repo: tuple[Path, Callable[..., str]],
) -> None:
    repo, commit = signed_repo
    commit(message="change\n\nCo-authored-by: Other <other@example.com>")
    result = _run_gate(repo, "Commit messages name only the commit identity")
    assert result.returncode == 1
    assert "names an address other than the commit identity" in result.stdout


def test_allowed_signer_matches_local_public_key_when_present() -> None:
    allowed = ROOT / ".github" / "allowed_signers"
    identity, key = allowed.read_text(encoding="utf-8").split(maxsplit=1)
    assert identity == COMMIT_IDENTITY
    public_key = Path.home() / ".ssh" / "id_ed25519_signing.pub"
    if public_key.exists():
        assert key.strip() == public_key.read_text(encoding="utf-8").strip()


def test_existing_branch_commits_verify_against_allowed_signers() -> None:
    if _git(ROOT, "rev-parse", "origin/main").returncode != 0:
        pytest.skip("origin/main is absent")
    result = _git(
        ROOT,
        "-c",
        "gpg.ssh.allowedSignersFile=.github/allowed_signers",
        "log",
        "--format=%G?",
        "origin/main..HEAD",
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip()
    assert all(state == "G" for state in result.stdout.split())


def test_private_name_in_tmp_tree_fails_without_printing_name(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "file.txt").write_text("zebra-quokka\n", encoding="utf-8")
    _git_output(tree, "init")
    _git_output(tree, "add", ".")
    result = subprocess.run(
        ["python3", str(TOOL), "--root", str(tree), "--no-default-file"],
        env={**os.environ, "PRIVATE_NAMES": "zebra-quokka"},
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 1
    assert "zebra-quokka" not in result.stdout + result.stderr


def test_private_name_tool_accepts_clean_tmp_tree(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "file.txt").write_text("clean\n", encoding="utf-8")
    _git_output(tree, "init")
    _git_output(tree, "add", ".")
    result = subprocess.run(
        ["python3", str(TOOL), "--root", str(tree), "--no-default-file"],
        env={**os.environ, "PRIVATE_NAMES": "zebra-quokka"},
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0
    assert "none in tree" in result.stdout


def test_private_name_tool_returns_two_without_any_names(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    _git_output(tree, "init")
    result = subprocess.run(
        ["python3", str(TOOL), "--root", str(tree), "--no-default-file"],
        env={**os.environ, "PRIVATE_NAMES": "", "FORBIDDEN_TERMS": ""},
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 2
    assert "this check proved nothing" in result.stderr
