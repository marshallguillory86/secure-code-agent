"""A flag accepted on a path that ignores it is worse than no flag.

`--target` names an *agent* for `--init-agent-standards` (codex, claude-code,
cursor …). On an audit run argparse still accepted it and nothing read it, so:

    secure-code-agent --target /some/repo

audited the **current directory** and printed a grade for it. Nothing was
wrong with the output except that it described a repository the operator had
not asked about.

It was found by using the tool. A 136,000-line control was audited with
`--target <control>` from a shell whose working directory happened to be that
control, so the flag appeared to work; the same command run from elsewhere
graded the wrong tree. That coincidence is exactly what keeps a bug like this
alive, and it is why the check below is structural rather than a single case.
"""

from __future__ import annotations

import pytest

from secure_code_audit import cli


def test_target_on_an_audit_run_is_refused(capsys):
    exit_code = cli.main(["--target", "/some/repo"])

    assert exit_code == 2
    assert "not a repository to audit" in capsys.readouterr().err


def test_the_refusal_shows_the_command_that_would_have_worked(capsys):
    """An operator who hits this must not have to read --help to recover."""
    cli.main(["--target", "/some/repo"])

    assert "secure-code-agent /some/repo" in capsys.readouterr().err


def test_target_still_works_for_what_it_is_for(tmp_path):
    exit_code = cli.main(
        [
            "--init-agent-standards",
            "--target",
            "codex",
            "--instructions-output-dir",
            str(tmp_path),
        ]
    )

    assert exit_code == 0
    assert list(tmp_path.iterdir()), "nothing was written"


def test_nothing_is_scanned_when_the_flag_is_refused(tmp_path, monkeypatch):
    """The refusal must come before any scanner runs.

    Returning 2 after auditing the wrong tree would still have written a
    report into it.
    """
    monkeypatch.chdir(tmp_path)

    def explode(*_args, **_kwargs):  # pragma: no cover - must not be reached
        raise AssertionError("an audit started despite the refusal")

    monkeypatch.setattr(cli, "_do_audit", explode)

    assert cli.main(["--target", "/some/repo"]) == 2


# ---------------------------------------------------------------------------
# The structural rule
# ---------------------------------------------------------------------------

#: Flags that belong to `--init-agent-standards` and are meaningless to an
#: audit. Each must either be read by the audit path or refused by it.
INIT_ONLY = ("--target", "--instructions-output-dir")


@pytest.mark.parametrize("flag", INIT_ONLY)
def test_an_init_only_flag_is_declared_as_such_in_its_help(flag: str):
    """Half the fix is the error; the other half is the help text that stops
    the operator reaching for it."""
    parser = cli._parser()
    action = next(a for a in parser._actions if flag in a.option_strings)

    assert action.help, f"{flag} has no help text"
    assert "--init-agent-standards" in action.help, (
        f"{flag} does not say which mode it belongs to, which is how --target "
        f"came to read as 'the repository to audit'"
    )
