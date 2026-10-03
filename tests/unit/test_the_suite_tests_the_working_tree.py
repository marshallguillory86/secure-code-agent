"""The suite must test the code in this checkout, not an installed copy.

Nothing in `[tool.pytest.ini_options]` put `src` on the import path, so bare
`pytest` from the repository root imported whichever `secure_code_audit` the
interpreter happened to have. On a developer machine with an editable install
that is the working tree and everything looks fine; in any environment
carrying a plain, older install it is *that* copy, and the suite silently
grades code nobody is editing.

It had already happened. maintainability-agent runs this repository's declared
test command from its own virtualenv, which holds a non-editable install, and
reported the suite failing on a bug fixed in #59 — the fix was in the
checkout, the failure was in site-packages. So the declared test command was
not reproducible, and `test_effectiveness` stayed unmeasured because of it.
"""

from __future__ import annotations

import secure_code_audit

REPO_SRC = "/src/secure_code_audit/"


def test_the_package_under_test_is_the_one_in_this_checkout():
    """Fails loudly when an installed copy shadows the working tree.

    Prevents the defect where a green suite says nothing about the code in
    the repository, because the import resolved somewhere else entirely.
    """
    resolved = str(secure_code_audit.__file__)
    assert REPO_SRC in resolved, (
        "the suite imported secure_code_audit from outside this checkout's "
        f"src/ — it is testing an installed copy at {resolved}"
    )
    assert "site-packages" not in resolved, (
        f"the suite imported secure_code_audit from site-packages: {resolved}"
    )
