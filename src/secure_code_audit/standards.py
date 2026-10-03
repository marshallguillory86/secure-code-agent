"""Standards taxonomy — CWE, OWASP Top 10, OWASP ASVS, NIST SSDF.

Maps known scanner rule ids to canonical standards. The mapping table provides
fingerprint inputs, category routing, severity weighting, and
remediation-prompt context when a defensible mapping exists.

The map lives as reviewed Python data and ships in the wheel. Operator-defined
rule packs are not implemented in this release.

See docs/standards.md for the citations.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from secure_code_audit.findings import Category, Confidence, Severity

# --- CWE Top 25 (2025) -----------------------------------------------------
# Source: https://cwe.mitre.org/top25/
# Used as a 1.25× scoring multiplier — see docs/scoring.md.

CWE_TOP25_2025: frozenset[str] = frozenset(
    {
        "CWE-79",
        "CWE-787",
        "CWE-89",
        "CWE-352",
        "CWE-22",
        "CWE-125",
        "CWE-78",
        "CWE-416",
        "CWE-862",
        "CWE-434",
        "CWE-94",
        "CWE-20",
        "CWE-77",
        "CWE-287",
        "CWE-269",
        "CWE-502",
        "CWE-200",
        "CWE-863",
        "CWE-918",
        "CWE-119",
        "CWE-476",
        "CWE-798",
        "CWE-190",
        "CWE-400",
        "CWE-306",
    }
)


# --- OWASP Top 10 (2021) bucket id → URL ----------------------------------
OWASP_TOP10_2021_URL = "https://owasp.org/Top10/2021/"

OWASP_TOP10_2021: dict[str, str] = {
    "A01": "A01:2021-Broken Access Control",
    "A02": "A02:2021-Cryptographic Failures",
    "A03": "A03:2021-Injection",
    "A04": "A04:2021-Insecure Design",
    "A05": "A05:2021-Security Misconfiguration",
    "A06": "A06:2021-Vulnerable and Outdated Components",
    "A07": "A07:2021-Identification and Authentication Failures",
    "A08": "A08:2021-Software and Data Integrity Failures",
    "A09": "A09:2021-Security Logging and Monitoring Failures",
    "A10": "A10:2021-Server-Side Request Forgery (SSRF)",
}


# --- Standards mapping entry ----------------------------------------------
#: Exactly the fields a data row may carry. Anything else is a typo, and a
#: typo that is ignored silently downgrades a curated rule to an unmapped one.
_ROW_KEYS = frozenset(
    {
        "scanner",
        "rule_id",
        "canonical_cwe",
        "owasp_top10",
        "asvs_section",
        "nist_ssdf",
        "category",
        "severity",
        "confidence",
        "short_desc",
        "fix_hint",
    }
)


@dataclass(frozen=True)
class StandardsEntry:
    canonical_cwe: str | None
    owasp_top10: str | None
    asvs_section: str | None
    nist_ssdf: str | None
    category: Category
    severity: Severity  # default; scanner-emitted severity overrides
    confidence: Confidence  # default
    short_desc: str
    fix_hint: str | None = None


# --- The mapping table -----------------------------------------------------
# Shipped as data, not code: `data/standards.yaml`. It was 416 lines of Python
# here, which meant an operator could not add a rule without a package
# release, and Semgrep alone publishes thousands of them
# (`docs/product-intent.md` §8 question 3, D32).
#
# Indexed by (scanner_name, rule_id): lowercase scanner name, and the exact
# rule id as the scanner emits it.
#
# Adding a rule:
#   1. Add an entry to `data/standards.yaml` with its CWE, OWASP id, ASVS
#      section and SSDF practice.
#   2. Add an entry to the matching tier in docs/scanners.md.
#   3. Add a fixture in tests/fixtures/<scanner>/.
#
# An operator extends the table without touching this file, by pointing
# `standards.overlay` at their own YAML. An overlay may add entries and may
# not restate severity, confidence or category — see D32.

_DATA_FILE = Path(__file__).parent / "data" / "standards.yaml"


def _entry_from_row(row: dict, source: str, index: int) -> tuple[tuple[str, str], StandardsEntry]:
    """One `(key, entry)` pair from one data row, or a `ValueError` naming it.

    Fails closed on an unparseable row. A mapping table that silently drops a
    malformed entry reports findings as unmapped — no CWE, no OWASP, no fix
    hint — which reads exactly like a rule nobody has curated yet. The row
    number and the file are in every message because this file is now
    something an operator edits.
    """
    where = f"{source}: entry #{index}"
    scanner = str(row.get("scanner", "")).strip().lower()
    rule_id = str(row.get("rule_id", "")).strip()
    if not scanner or not rule_id:
        raise ValueError(f"{where}: 'scanner' and 'rule_id' are both required.")

    unknown = sorted(set(row) - _ROW_KEYS)
    if unknown:
        raise ValueError(
            f"{where} ({scanner}/{rule_id}): unknown field(s) {', '.join(unknown)}. "
            f"Allowed: {', '.join(sorted(_ROW_KEYS))}."
        )
    if not str(row.get("short_desc", "")).strip():
        raise ValueError(f"{where} ({scanner}/{rule_id}): 'short_desc' is required.")

    try:
        entry = StandardsEntry(
            canonical_cwe=row.get("canonical_cwe"),
            owasp_top10=row.get("owasp_top10"),
            asvs_section=row.get("asvs_section"),
            nist_ssdf=row.get("nist_ssdf"),
            category=Category(row["category"]),
            severity=Severity(row["severity"]),
            confidence=Confidence(row["confidence"]),
            short_desc=row["short_desc"],
            fix_hint=row.get("fix_hint"),
        )
    except (KeyError, ValueError) as exc:
        raise ValueError(f"{where} ({scanner}/{rule_id}): {exc}") from exc
    return (scanner, rule_id), entry


def _load_table(path: Path) -> dict[tuple[str, str], StandardsEntry]:
    """The shipped mapping table. Raises rather than returning a partial one."""
    import yaml

    document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    rows = document.get("entries") or []
    if not isinstance(rows, list):
        raise ValueError(f"{path}: 'entries' must be a list.")

    table: dict[tuple[str, str], StandardsEntry] = {}
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError(f"{path}: entry #{index}: must be a mapping.")
        key, entry = _entry_from_row(row, str(path), index)
        if key in table:
            # Two rows for one rule means one of them is being ignored, and
            # which one depends on file order. That is not a table.
            raise ValueError(f"{path}: entry #{index}: duplicate rule {key[0]}/{key[1]}.")
        table[key] = entry
    return table


_MAP: dict[tuple[str, str], StandardsEntry] = _load_table(_DATA_FILE)


def lookup(scanner: str, rule_id: str) -> StandardsEntry | None:
    """Resolve (scanner, rule_id) → StandardsEntry, with wildcard fallback.

    Order: exact match → (scanner, "*") wildcard → None.
    """
    exact = _MAP.get((scanner.lower(), rule_id))
    if exact is not None:
        return exact
    return _MAP.get((scanner.lower(), "*"))


#: Child CWEs this project maps to, and the Top-25 entry each is a ChildOf.
#:
#: The Top-25 list names classes, and a scanner names the specific weakness
#: inside one. CWE-95 ("Eval Injection") is a documented ChildOf CWE-94
#: ("Improper Control of Generation of Code"), which is on the list — so a
#: confirmed eval injection *is* a Top-25 weakness, and a membership test
#: that only compares strings says it is not.
#:
#: This is deliberately a hand-checked handful rather than an imported CWE
#: hierarchy. Every entry is a relationship stated in the MITRE definition of
#: the child, and each is used by a rule this project actually maps. Adding a
#: parent here widens the 1.25x bonus, so it is a decision, not a lookup.
_TOP25_PARENT: dict[str, str] = {
    # cwe.mitre.org/data/definitions/95.html — ChildOf 94
    "CWE-95": "CWE-94",
    # cwe.mitre.org/data/definitions/77.html is itself on the list; 78 is the
    # OS-command child and is also listed, so neither needs an entry here.
}


def is_top25(canonical_cwe: str | None) -> bool:
    """Is this CWE on the MITRE Top 25 (2025) list, directly or as a child?

    Correcting Bandit's B102/B307 from CWE-78 to CWE-95 was right on the
    weakness and would have quietly removed the Top-25 bonus from every
    eval/exec finding in the corpus — CWE-78 is on the list and CWE-95 is
    not. Losing the bonus for the *reason* "we now describe the weakness
    accurately" is the wrong trade, and CWE-95 is a child of CWE-94, which
    is listed. So membership follows the relationship.
    """
    if canonical_cwe is None:
        return False
    if canonical_cwe in CWE_TOP25_2025:
        return True
    return _TOP25_PARENT.get(canonical_cwe, "") in CWE_TOP25_2025


def cwe_url(canonical_cwe: str) -> str:
    """Cite a CWE id — e.g. 'CWE-89' → MITRE definition URL."""
    num = canonical_cwe.split("-", 1)[1] if "-" in canonical_cwe else canonical_cwe
    return f"https://cwe.mitre.org/data/definitions/{num}.html"


def owasp_url(owasp_id: str) -> str:
    """OWASP Top 10 bucket id → deep-link URL. Falls back to the index
    when the id doesn't map to a known bucket (e.g. legacy 2017 ids)."""
    bucket = owasp_id.split(":", 1)[0] if ":" in owasp_id else owasp_id
    label = OWASP_TOP10_2021.get(bucket)
    if not label:
        return OWASP_TOP10_2021_URL
    # 'A03:2021-Injection' → 'A03_2021-Injection' for the URL slug.
    slug = label.replace(":", "_").replace(" ", "_")
    return f"{OWASP_TOP10_2021_URL}{slug}/"


def owasp_label(owasp_id: str) -> str:
    """'A03' → 'A03:2021-Injection'. Returns the id unchanged if not mapped."""
    bucket = owasp_id.split(":", 1)[0] if ":" in owasp_id else owasp_id
    return OWASP_TOP10_2021.get(bucket, owasp_id)


# --- CWE → OWASP Top 10 (2021) --------------------------------------------
# Each 2021 category is *defined* by a list of CWEs, published with the Top 10
# itself. This is that mapping, restricted to the CWEs the floor scanners
# actually emit — a partial table that says "unknown" honestly is worth more
# than a complete one built by guessing.
#
# Source: https://owasp.org/Top10/ — each category page lists its "Mapped
# CWEs". Where a CWE appears under more than one category the more specific
# one is used, which is the convention the category pages themselves follow.
_CWE_TO_OWASP: dict[str, str] = {
    # A01 Broken Access Control
    "CWE-22": "A01",
    "CWE-200": "A01",
    "CWE-284": "A01",
    "CWE-285": "A01",
    "CWE-352": "A01",
    "CWE-359": "A01",
    "CWE-425": "A01",
    "CWE-639": "A01",
    "CWE-862": "A01",
    "CWE-863": "A01",
    # A02 Cryptographic Failures
    "CWE-259": "A02",
    "CWE-295": "A02",
    "CWE-319": "A02",
    "CWE-326": "A02",
    "CWE-327": "A02",
    "CWE-328": "A02",
    "CWE-330": "A02",
    "CWE-331": "A02",
    "CWE-338": "A02",
    "CWE-798": "A02",
    "CWE-916": "A02",
    # A03 Injection
    "CWE-77": "A03",
    "CWE-78": "A03",
    "CWE-79": "A03",
    "CWE-80": "A03",
    "CWE-88": "A03",
    "CWE-89": "A03",
    "CWE-90": "A03",
    "CWE-91": "A03",
    "CWE-94": "A03",
    "CWE-95": "A03",
    "CWE-96": "A03",
    "CWE-113": "A03",
    "CWE-116": "A03",
    "CWE-643": "A03",
    "CWE-917": "A03",
    # A04 Insecure Design
    "CWE-209": "A04",
    "CWE-256": "A04",
    "CWE-501": "A04",
    "CWE-522": "A04",
    # A05 Security Misconfiguration
    "CWE-16": "A05",
    "CWE-260": "A05",
    "CWE-611": "A05",
    "CWE-614": "A05",
    "CWE-732": "A05",
    "CWE-776": "A05",
    "CWE-1004": "A05",
    # A06 Vulnerable and Outdated Components
    "CWE-1035": "A06",
    "CWE-1104": "A06",
    # A07 Identification and Authentication Failures
    "CWE-287": "A07",
    "CWE-290": "A07",
    "CWE-297": "A07",
    "CWE-306": "A07",
    "CWE-307": "A07",
    "CWE-384": "A07",
    "CWE-521": "A07",
    "CWE-613": "A07",
    "CWE-620": "A07",
    # A08 Software and Data Integrity Failures
    "CWE-345": "A08",
    "CWE-347": "A08",
    "CWE-494": "A08",
    "CWE-502": "A08",
    "CWE-829": "A08",
    # A09 Security Logging and Monitoring Failures
    "CWE-117": "A09",
    "CWE-223": "A09",
    "CWE-532": "A09",
    "CWE-778": "A09",
    # A10 Server-Side Request Forgery
    "CWE-918": "A10",
}


def owasp_for_cwe(canonical_cwe: str | None) -> str | None:
    """Derive an OWASP Top 10 (2021) category key from a CWE, or None.

    Returns the short key — "A03", the same shape the curated map stores and
    `owasp_label()` expands — so a derived value and a curated one are
    indistinguishable downstream.

    Used only where the curated map has no OWASP id of its own. Returning
    None is a normal outcome and is the point: Bandit files `assert_used`
    under CWE-703 ("improper check for unusual conditions"), which is a real
    weakness class and belongs to no Top 10 category. Inventing one would put
    a standard's name behind a claim it does not make.
    """
    if canonical_cwe is None:
        return None
    return _CWE_TO_OWASP.get(canonical_cwe)


def categories_for_scanner(scanner: str) -> frozenset[Category]:
    """Which categories this scanner has mapped rules for.

    Used to work out what a run could have measured. Derived from the map
    rather than written down a second time: the hand-maintained copy claimed
    `builtin_rules` covered `secrets` and `config_iac`, which it never has —
    its rules are Python and shell language primitives — and omitted
    `supply_chain`, which it does cover. An IaC repository with a
    `public-read` S3 bucket and an open security group therefore scored
    `config_iac` 5.0 with no IaC scanner installed.
    """
    return frozenset(
        entry.category for (name, _rule), entry in _MAP.items() if name == scanner.lower()
    )
