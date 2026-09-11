"""A category nothing could read must not be graded.

The rule the whole tool rests on, applied to the categories: a scanner that
was never installed measured nothing, so the category it would have covered
has no score rather than a perfect one.

Found by auditing an infrastructure repository. A `Dockerfile` with `USER
root` and `chmod 777`, and a `main.tf` with a `public-read` S3 bucket and a
0.0.0.0/0 ingress rule, scored **config_iac 5.0** with neither checkov nor
hadolint installed.

The cause was a hand-written list. `builtin_rules` declares its domain as
`multiple`, and the code translated that into a fixed set of four
categories which was wrong in both directions: it claimed `secrets` and
`config_iac`, neither of which builtin_rules has ever had a rule for — its
rules are Python and shell language primitives — and omitted `supply_chain`,
which it does cover via `sca.shell.curl_pipe_sh`.

The set is now derived from the standards map, so it cannot drift from the
rules it describes.
"""

from __future__ import annotations

from secure_code_audit.findings import Category
from secure_code_audit.standards import categories_for_scanner


def test_builtin_rules_covers_what_its_rules_actually_cover():
    covered = categories_for_scanner("builtin_rules")

    assert Category.CODE_VULNERABILITIES in covered
    assert Category.CRYPTO in covered
    assert Category.SUPPLY_CHAIN in covered


def test_builtin_rules_does_not_claim_iac():
    """It has never had an IaC rule. Claiming the category graded an
    unexamined Terraform file 5.0."""
    assert Category.CONFIG_IAC not in categories_for_scanner("builtin_rules")


def test_builtin_rules_does_not_claim_secrets():
    """Also claimed by the old hand-written list, also never true —
    gitleaks and trufflehog are the secrets scanners."""
    assert Category.SECRETS not in categories_for_scanner("builtin_rules")


def test_a_scanner_with_no_mapped_rules_covers_nothing():
    """Silence, not a guess."""
    assert categories_for_scanner("a-scanner-that-does-not-exist") == frozenset()


def test_the_lookup_is_case_insensitive_on_the_scanner_name():
    assert categories_for_scanner("BUILTIN_RULES") == categories_for_scanner("builtin_rules")


def test_every_category_claimed_is_backed_by_a_rule():
    """The property that makes this drift-proof: whatever the map says a
    scanner covers is exactly what its rules are categorised as, because it
    is the same data read twice rather than two lists kept in step."""
    from secure_code_audit.standards import _MAP

    for scanner in {name for name, _ in _MAP}:
        claimed = categories_for_scanner(scanner)
        actual = {entry.category for (name, _r), entry in _MAP.items() if name == scanner}
        assert claimed == actual, scanner
