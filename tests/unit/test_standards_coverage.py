"""A scanner that tells us the CWE must not have it thrown away.

`docs/product-intent.md` §5 promises *"Findings map to CWE, OWASP Top 10,
OWASP ASVS, and NIST SSDF"* and the README leads with *"Anchored to NIST SSDF ·
OWASP ASVS · OWASP Top 10 · MITRE CWE Top 25"*. Measured against the
calibration corpus, **69 of 486 real findings carried a CWE — 14%.**

The cause was not that the mapping is hard. Bandit publishes a CWE for every
one of its ~70 plugins and `standards.py` curated seven of them; gosec
publishes one per rule and the adapter appended it to the *message string* and
then dropped it. Both tools were handing us the answer and both were ignored.

The curated map still wins where it exists — it is reviewed and it is the only
source that also carries OWASP, ASVS, SSDF and a fix hint. Upstream's CWE is
the fallback, because a defensible CWE beats none.
"""

from __future__ import annotations

import json
from pathlib import Path

from secure_code_audit.config import Config
from secure_code_audit.findings import Category, Confidence, Severity
from secure_code_audit.scanners.bandit_scanner import BanditScanner, _cwe_of
from secure_code_audit.scanners.base import Scanner
from secure_code_audit.standards import lookup, owasp_for_cwe


class _Probe(Scanner):
    name = "bandit"  # so the curated map is reachable
    binary = None

    def scan(self, target: Path, config: Config):  # pragma: no cover - unused
        raise NotImplementedError


def _finding(**kw):
    probe = _Probe()
    probe.configure(Path("/tmp"), Config())
    return probe._make_finding(
        message="m",
        file_path=Path("/tmp/a.py"),
        line_start=1,
        line_end=1,
        code_snippet=None,
        **kw,
    )


# ---------------------------------------------------------------------------
# Precedence between the three sources of a CWE
# ---------------------------------------------------------------------------


def test_the_curated_map_outranks_what_the_scanner_says():
    """B602 is curated as CWE-78. Bandit agrees, but the map is authoritative
    because it also carries the OWASP, ASVS and SSDF anchoring."""
    finding = _finding(rule_id="B602", scanner_cwe="CWE-999")

    assert finding.canonical_cwe == "CWE-78"
    assert finding.asvs_section == "V5.3.8"
    assert finding.nist_ssdf == "PW.5.1"


def test_the_scanner_cwe_fills_in_where_the_map_is_silent():
    """B101 is not curated, and this is the 86% case."""
    finding = _finding(rule_id="B101", scanner_cwe="CWE-703")

    assert lookup("bandit", "B101") is None
    assert finding.canonical_cwe == "CWE-703"


def test_an_explicit_override_outranks_everything():
    """Semgrep asserts its own rule metadata and must keep winning."""
    finding = _finding(rule_id="B602", cwe_override="CWE-1234", scanner_cwe="CWE-999")

    assert finding.canonical_cwe == "CWE-1234"


def test_no_cwe_anywhere_is_still_allowed():
    """Not every finding has one, and inventing one would be worse."""
    assert _finding(rule_id="B9999").canonical_cwe is None


# ---------------------------------------------------------------------------
# OWASP derived from the CWE
# ---------------------------------------------------------------------------


def test_owasp_is_derived_from_the_cwe_when_the_map_has_none():
    finding = _finding(rule_id="B101", scanner_cwe="CWE-327")

    assert finding.owasp_top10 == "A02"


def test_a_derived_owasp_uses_the_same_shape_as_a_curated_one():
    """The map stores "A03" and `owasp_label()` expands it. A derived value
    that returned the full label instead would render as
    "A03:2021-Injection:2021-Injection" in one renderer and be unrecognised
    by the other."""
    curated = _finding(rule_id="B602")
    derived = _finding(rule_id="B101", scanner_cwe="CWE-78")

    assert curated.owasp_top10 == derived.owasp_top10 == "A03"


def test_a_cwe_outside_the_top_ten_derives_nothing():
    """CWE-703 is a real weakness class in no Top 10 category. Forcing one
    would put a standard's name behind a claim it does not make."""
    assert owasp_for_cwe("CWE-703") is None
    assert _finding(rule_id="B101", scanner_cwe="CWE-703").owasp_top10 is None


def test_the_top25_bonus_reaches_findings_it_previously_could_not():
    """`cwe_top25` is a 1.25x scoring multiplier keyed on the CWE. With 86% of
    findings carrying no CWE it could not fire for them at all."""
    assert _finding(rule_id="B999", scanner_cwe="CWE-78").cwe_top25 is True
    assert _finding(rule_id="B999", scanner_cwe="CWE-703").cwe_top25 is False


# ---------------------------------------------------------------------------
# Parsing what Bandit actually emits
# ---------------------------------------------------------------------------


def test_bandit_issue_cwe_is_read_from_its_real_shape():
    assert _cwe_of({"issue_cwe": {"id": 78, "link": "..."}}) == "CWE-78"


def test_a_bandit_result_without_a_cwe_is_not_invented():
    assert _cwe_of({}) is None
    assert _cwe_of({"issue_cwe": None}) is None
    assert _cwe_of({"issue_cwe": {}}) is None
    assert _cwe_of({"issue_cwe": "CWE-78"}) is None  # not the documented shape


def test_the_bandit_adapter_carries_the_cwe_end_to_end(tmp_path, monkeypatch):
    """Parse a real Bandit payload rather than trusting the helper alone."""
    payload = {
        "results": [
            {
                "filename": str(tmp_path / "s.py"),
                "line_number": 3,
                "line_range": [3],
                "test_id": "B324",
                "issue_text": "weak hash",
                "issue_severity": "HIGH",
                "issue_confidence": "HIGH",
                "issue_cwe": {"id": 327, "link": "..."},
                "code": "hashlib.md5(b'x')",
            }
        ]
    }

    scanner = BanditScanner()
    scanner.configure(tmp_path, Config())
    monkeypatch.setattr(
        scanner,
        "_exec",
        lambda *a, **k: type(
            "R", (), {"returncode": 0, "stdout": json.dumps(payload), "stderr": ""}
        )(),
    )
    monkeypatch.setattr(scanner, "is_available", lambda: True)

    (finding,) = scanner.scan(tmp_path, Config()).findings

    assert finding.canonical_cwe == "CWE-327"
    assert finding.owasp_top10 == "A02"
    assert finding.severity is Severity.HIGH
    assert finding.confidence is Confidence.HIGH
    assert finding.category is Category.CODE_VULNERABILITIES


# ---------------------------------------------------------------------------
# The structural block
# ---------------------------------------------------------------------------


def test_an_adapter_that_reads_a_cwe_must_pass_it_to_the_constructor():
    """gosec is why this exists.

    It parsed `issue["cwe"]["id"]`, formatted it into the message text for a
    human to read, and never set `canonical_cwe` — so scoring, the Top-25
    bonus and the SARIF taxonomy all saw a finding with no CWE while the
    report showed one. Reading a CWE and not passing it on is the specific
    mistake; this asserts no adapter makes it again.
    """
    import inspect

    from secure_code_audit import scanners as registry

    # A *quoted* cwe key is a read of scanner output. The bare word is not:
    # `builtin_rules` says "targets a single CWE" in a docstring and gets its
    # CWEs from the curated map, which is correct and must not trip this.
    reads = ('"cwe"', "'cwe'", "issue_cwe", '"CWE"')

    offenders = []
    for name, cls in registry.SCANNERS.items():
        source = inspect.getsource(inspect.getmodule(cls))
        reads_cwe = any(token in source for token in reads)
        passes_cwe = "scanner_cwe=" in source or "cwe_override=" in source
        if reads_cwe and not passes_cwe:
            offenders.append(name)

    assert offenders == [], (
        f"{offenders} read a CWE from their scanner but never pass it to "
        f"_make_finding via scanner_cwe= or cwe_override=, so it is dropped "
        f"before it reaches scoring, the Top-25 bonus or SARIF"
    )
