"""The profile version has to move when the rules do.

D10 ships the offline rules as a versioned, digest-identified profile, and
`PROFILE_VERSION` says in its own docstring: *"Bump when rules are added,
removed, or their meaning changes. A rule whose pattern is broadened has
changed meaning even if its id is unchanged, and a report that cites an
unchanged version after that is claiming a comparison it cannot support."*

Nothing enforced it. `sca.offline.ruby.code-injection` was narrowed to stop
matching `class_eval(&block)` — a meaning change by that docstring's own
definition, and one that removed four findings from Sinatra — and the profile
went on citing 1.1.0 in every report. Two audits a month apart would have
carried the same profile identity and produced different findings, which is
precisely the comparison P6 promises is reproducible.

So the digest is pinned here. Editing the ruleset fails this test until the
version is bumped and the pin updated in the same change, which is the
deliberate act the docstring asks for. This is not a checksum of correctness —
it is a tripwire on forgetting.
"""

from __future__ import annotations

from secure_code_audit import ruleset
from secure_code_audit.scanners.semgrep_scanner import offline_ruleset_path

#: sha256 of `data/semgrep-offline.yaml` as shipped at PROFILE_VERSION.
#: Update this and PROFILE_VERSION together, never one alone.
PINNED = {
    "1.2.0": "e861a891559feaa6cfce801e07ec4d63601a608b3e56912b0a78d1bedf105b77",
}


def test_the_shipped_ruleset_matches_the_version_it_claims():
    profile = ruleset.describe(offline_ruleset_path())

    assert profile is not None, "the offline ruleset is not present in the package"
    assert profile.version in PINNED, (
        f"PROFILE_VERSION is {profile.version!r} but no digest is pinned for it. "
        f"Add the new version to PINNED with the digest below."
    )
    assert profile.digest == PINNED[profile.version], (
        f"the offline ruleset changed but still claims {profile.version}.\n"
        f"  expected {PINNED[profile.version]}\n"
        f"  actual   {profile.digest}\n"
        f"Bump PROFILE_VERSION and add the new digest to PINNED. If the change "
        f"is genuinely cosmetic — a comment, whitespace — it still changes the "
        f"digest, so it still needs a patch bump: reports cite the digest."
    )


def test_a_report_can_name_the_exact_rules_that_produced_it():
    """The identity has to be usable, not just present.

    `cite()` is what lands in the coverage block, and an operator reading a
    finding six months later needs all three parts: which profile, which
    revision of it, and which bytes.
    """
    profile = ruleset.describe(offline_ruleset_path())

    assert profile.cite() == f"sca-offline@{profile.version} ({profile.digest[:12]})"
    assert profile.rule_count > 0
    assert profile.cwes, "no rule declares a CWE, so nothing can be traced to a standard"
