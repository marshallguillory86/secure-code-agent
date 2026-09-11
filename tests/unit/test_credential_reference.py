"""A variable name is not a credential.

`gitleaks.curl-auth-user` fires CRITICAL on `curl -sS -u "$SONAR_TOKEN:"` in a
GitHub Actions workflow. No credential is present — `$SONAR_TOKEN` is how you
write *not* putting one there, and it is the recommended idiom. Reported
independently on two repositories on the same day, five occurrences on one.

**Why this is worth code rather than a suppression.** D17 made `secrets`
count-like: it normalizes by `sqrt(LOC/1000)` rather than by size, so one
false critical now costs roughly two grade points on a 100,000-line repository
where it previously cost two tenths. Raising a category's weight raises the
cost of being wrong in it, and this is the matching precision work.

**Why it reads the file.** Gitleaks runs with `--redact`, so the matched text
never reaches the report: the message is `curl -sS -u REDACTED`, and the
variable name is exactly what got redacted. The only way to tell a reference
from a value is to look at the line, which is what `verify._is_silenced`
already does for a different question.

**Why REVIEW and not ACCEPT.** The finding stays in the work order, stays in
the report, and still escalates through `fail_on_category: [secrets]` from any
axis. Demotion moves it down the list; it does not make it disappear.

**Why the fixtures are assembled rather than written out.** The first version
of this file spelled the offending lines as literals, and gitleaks flagged
twelve criticals in it — in the test file for the rule about that rule. CI
caught it, which is the third time in this project that documenting a
vulnerable pattern created one. `_auth` builds each line from parts so no
literal in this source matches the rule, while the file written to disk —
which is what `tier_of` actually reads — still does.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from secure_code_audit.findings import Category, Confidence, Finding, Severity
from secure_code_audit.triage import Tier, reason_for, tier_of


def _secret_at(path: Path, line: int = 1) -> Finding:
    return Finding(
        rule_id="gitleaks.curl-auth-user",
        scanner="gitleaks",
        fingerprint="fp",
        canonical_cwe="CWE-798",
        owasp_top10="A07",
        asvs_section=None,
        nist_ssdf=None,
        category=Category.SECRETS,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        file_path=path,
        line_start=line,
        line_end=line,
        code_snippet="curl -sS -u REDACTED",
        message="Detected a curl auth user: curl -sS -u REDACTED",
    )


#: Assemble `curl -<flags> -u "<credential>" <url>` without ever spelling it.
_CURL = "cur" + "l"
_AUTH_FLAG = "-" + "u"


def _auth(credential: str, flags: str = "-sS", url: str = "https://example.invalid/api") -> str:
    return f'{_CURL} {flags} {_AUTH_FLAG} "{credential}" {url}'


#: Likewise for a literal credential, which must never appear whole here.
_LITERAL = "hunter" + "2" + "Passw" + "0" + "rd"


def _write(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "ci.yml"
    path.write_text(content, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# References are demoted
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        _auth("$SONAR_TOKEN:"),
        _auth("${SONAR_TOKEN}:", flags=""),
        _auth("${{ secrets.API_USER }}:${{ secrets.API_PASS }}"),
        _auth("${{ env.TOKEN }}:"),
        _auth("%API_TOKEN%:"),
        'requests.get(url, auth=(os.environ["USER"], os.environ["PASS"]))',
        "fetch(url, {headers: {auth: process.env.TOKEN}})",
        "Net::HTTP.get(uri, ENV['API_TOKEN'])",
    ],
)
def test_a_variable_reference_is_reviewed_not_fixed(tmp_path, line: str):
    finding = _secret_at(_write(tmp_path, line + "\n"))

    assert tier_of(finding) is Tier.REVIEW


def test_the_reason_says_what_was_checked(tmp_path):
    finding = _secret_at(_write(tmp_path, _auth("$TOKEN:") + "\n"))

    reason = reason_for(finding)

    assert reason is not None
    assert "variable reference" in reason
    assert "reading the line back" in reason


# ---------------------------------------------------------------------------
# Real credentials are not
# ---------------------------------------------------------------------------


def test_a_literal_credential_stays_in_fix(tmp_path):
    finding = _secret_at(_write(tmp_path, _auth(f"admin:{_LITERAL}") + "\n"))

    assert tier_of(finding) is Tier.FIX


def test_a_reference_and_a_literal_on_one_line_stays_in_fix(tmp_path):
    """The dangerous case. Half of this line is done correctly, and that must
    not launder the other half."""
    finding = _secret_at(_write(tmp_path, _auth(f"$API_USER:{_LITERAL}") + "\n"))

    assert tier_of(finding) is Tier.FIX


def test_a_variable_name_alone_cannot_satisfy_the_literal_test(tmp_path):
    """`$VERY_LONG_VARIABLE_NAME` is twelve-plus token characters. If the
    references were not stripped before looking for a literal, every long
    variable name would re-promote itself and the demotion would never fire."""
    finding = _secret_at(_write(tmp_path, _auth("$A_VERY_LONG_TOKEN_NAME_INDEED:") + "\n"))

    assert tier_of(finding) is Tier.REVIEW


# ---------------------------------------------------------------------------
# It declines rather than guesses
# ---------------------------------------------------------------------------


def test_an_unreadable_file_does_not_demote(tmp_path):
    """A finding out of git history may point at a line the working tree no
    longer has. Absence of evidence is not evidence of a reference."""
    finding = _secret_at(tmp_path / "gone.yml")

    assert tier_of(finding) is Tier.FIX


def test_the_fixtures_never_appear_as_literals_in_this_source():
    """The defect that made this whole section necessary, guarded.

    Twelve criticals were flagged inside this file when its fixtures were
    spelled out. Assembling them is only a fix while it stays assembled, and
    the next person to add a case will reach for a literal.
    """
    source = Path(__file__).read_text(encoding="utf-8")

    assert _auth("$TOKEN:") not in source
    assert _LITERAL not in source


def test_a_line_number_past_the_end_does_not_demote(tmp_path):
    finding = _secret_at(_write(tmp_path, "one line\n"), line=99)

    assert tier_of(finding) is Tier.FIX


def test_a_directory_does_not_demote(tmp_path):
    finding = _secret_at(tmp_path)

    assert tier_of(finding) is Tier.FIX


def test_a_non_secrets_finding_is_untouched(tmp_path):
    """The check is scoped to `secrets`. An injection sink on a line that
    happens to mention `$PATH` is not a credential question."""
    path = _write(tmp_path, 'subprocess.call("ls " + $ARG, shell=True)\n')
    finding = _secret_at(path)
    code_finding = Finding(
        **{
            **{f.name: getattr(finding, f.name) for f in finding.__dataclass_fields__.values()},
            "category": Category.CODE_VULNERABILITIES,
            "rule_id": "B602",
        }
    )

    assert tier_of(code_finding) is Tier.FIX
