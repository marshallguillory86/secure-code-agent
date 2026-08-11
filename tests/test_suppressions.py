

def test_a_suppression_without_a_fingerprint_covers_the_whole_file_and_rule():
    """Documents the blast radius of the loose form, so choosing it is deliberate."""
    import datetime
    from pathlib import Path

    from secure_code_audit.suppressions import SuppressionRule

    class _F:
        rule_id = "gitleaks.generic-api-key"
        file_path = Path("api/tests/x.py")
        fingerprint = "unrelated0000000"

    rule = SuppressionRule(rule_id="gitleaks.generic-api-key", reason="r",
                           expires=datetime.date(2099, 1, 1), file="api/tests/x.py")
    assert rule.matches(_F()) is True


def test_a_fingerprinted_suppression_does_not_cover_a_different_secret():
    """The defect this closes: an entry justified for ONE test canary also hid any other secret
    the same rule found in the same file — a different line, different content, never reviewed.
    A suppression must not outgrow its stated reason."""
    import datetime
    from pathlib import Path

    from secure_code_audit.suppressions import SuppressionRule

    class _F:
        def __init__(self, fp):
            self.rule_id = "gitleaks.generic-api-key"
            self.file_path = Path("api/tests/x.py")
            self.fingerprint = fp

    rule = SuppressionRule(rule_id="gitleaks.generic-api-key", reason="r",
                           expires=datetime.date(2099, 1, 1), file="api/tests/x.py",
                           fingerprint="intended00000000")
    assert rule.matches(_F("intended00000000")) is True
    assert rule.matches(_F("someoneelse00000")) is False
