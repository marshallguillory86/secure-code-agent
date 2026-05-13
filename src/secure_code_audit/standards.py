"""Standards taxonomy — CWE, OWASP Top 10, OWASP ASVS, NIST SSDF.

Maps scanner rule ids to canonical standards. The mapping table is the
source of truth for: dedupe (canonical_cwe), category routing, severity
weighting, and remediation-prompt context.

The map lives as Python data (not JSON-on-disk) for v0.1 so it ships in
the wheel without a packaging tweak. v0.2 may externalize to JSON to
support operator-defined rule packs.

See docs/standards.md for the citations.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from secure_code_audit.findings import Category, Confidence, Severity


# --- CWE Top 25 (2025) -----------------------------------------------------
# Source: https://cwe.mitre.org/top25/
# Used as a 1.25× scoring multiplier — see docs/scoring.md.

CWE_TOP25_2025: frozenset[str] = frozenset({
    "CWE-79",  "CWE-787", "CWE-89",  "CWE-352", "CWE-22",
    "CWE-125", "CWE-78",  "CWE-416", "CWE-862", "CWE-434",
    "CWE-94",  "CWE-20",  "CWE-77",  "CWE-287", "CWE-269",
    "CWE-502", "CWE-200", "CWE-863", "CWE-918", "CWE-119",
    "CWE-476", "CWE-798", "CWE-190", "CWE-400", "CWE-306",
})


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
@dataclass(frozen=True)
class StandardsEntry:
    canonical_cwe: Optional[str]
    owasp_top10:   Optional[str]
    asvs_section:  Optional[str]
    nist_ssdf:     Optional[str]
    category:      Category
    severity:      Severity      # default; scanner-emitted severity overrides
    confidence:    Confidence    # default
    short_desc:    str
    fix_hint:      Optional[str] = None


# --- The mapping table -----------------------------------------------------
# Indexed by (scanner_name, rule_id). Keys must be lowercase scanner name +
# exact rule id as the scanner emits it.
#
# Adding a rule:
#   1. Add the (CWE id, OWASP id, ASVS section, SSDF practice) tuple.
#   2. Cite the scanner's docs URL in `references=` if non-obvious.
#   3. Add an entry to the matching tier in docs/scanners.md.
#   4. Add a fixture in tests/fixtures/<scanner>/.

_MAP: dict[tuple[str, str], StandardsEntry] = {

    # ----- Bandit ----------------------------------------------------------
    # Source: https://bandit.readthedocs.io/en/latest/plugins/index.html
    ("bandit", "B102"): StandardsEntry(
        canonical_cwe="CWE-78", owasp_top10="A03", asvs_section="V5.3.8",
        nist_ssdf="PW.5.1", category=Category.CODE_VULNERABILITIES,
        severity=Severity.HIGH, confidence=Confidence.MEDIUM,
        short_desc="Use of exec() — arbitrary code execution risk.",
        fix_hint="Eliminate exec() entirely. If dynamic dispatch is required, use a typed registry / function map.",
    ),
    ("bandit", "B301"): StandardsEntry(
        canonical_cwe="CWE-502", owasp_top10="A08", asvs_section="V5.5.1",
        nist_ssdf="PW.5.1", category=Category.CODE_VULNERABILITIES,
        severity=Severity.HIGH, confidence=Confidence.HIGH,
        short_desc="pickle.loads() on possibly-untrusted input — arbitrary code execution.",
        fix_hint="Replace pickle with JSON for data, or a signed/encrypted envelope for trusted state transfer.",
    ),
    ("bandit", "B303"): StandardsEntry(
        canonical_cwe="CWE-327", owasp_top10="A02", asvs_section="V6.2.5",
        nist_ssdf="PW.4.1", category=Category.CRYPTO,
        severity=Severity.MEDIUM, confidence=Confidence.HIGH,
        short_desc="MD5/SHA-1 used. Insecure for security purposes (collisions).",
        fix_hint="Use SHA-256 or BLAKE2 for non-password hashing. Use Argon2id for password hashing.",
    ),
    ("bandit", "B305"): StandardsEntry(
        canonical_cwe="CWE-327", owasp_top10="A02", asvs_section="V6.2.2",
        nist_ssdf="PW.4.1", category=Category.CRYPTO,
        severity=Severity.HIGH, confidence=Confidence.HIGH,
        short_desc="Use of insecure cipher mode (ECB).",
        fix_hint="Use authenticated encryption (AES-GCM or ChaCha20-Poly1305). Never ECB.",
    ),
    ("bandit", "B501"): StandardsEntry(
        canonical_cwe="CWE-295", owasp_top10="A07", asvs_section="V9.2.1",
        nist_ssdf="PW.4.1", category=Category.CRYPTO,
        severity=Severity.HIGH, confidence=Confidence.HIGH,
        short_desc="Requests call with verify=False — TLS cert validation disabled.",
        fix_hint="Remove verify=False. If self-signed cert is required, pass the trusted CA bundle explicitly.",
    ),
    ("bandit", "B602"): StandardsEntry(
        canonical_cwe="CWE-78", owasp_top10="A03", asvs_section="V5.3.8",
        nist_ssdf="PW.5.1", category=Category.CODE_VULNERABILITIES,
        severity=Severity.HIGH, confidence=Confidence.HIGH,
        short_desc="subprocess with shell=True and shell metacharacters — command injection.",
        fix_hint="Pass argv as a list and use shell=False. Never interpolate user input into a shell string.",
    ),
    ("bandit", "B608"): StandardsEntry(
        canonical_cwe="CWE-89", owasp_top10="A03", asvs_section="V5.3.5",
        nist_ssdf="PW.5.1", category=Category.CODE_VULNERABILITIES,
        severity=Severity.HIGH, confidence=Confidence.MEDIUM,
        short_desc="String-built SQL — possible injection.",
        fix_hint="Use parameterized queries ($1, ?, :name). Never interpolate user input into SQL strings.",
    ),

    # ----- pip-audit -------------------------------------------------------
    # Source: https://github.com/pypa/pip-audit
    # pip-audit emits per-CVE findings — they all share CWE-1104 (Use of
    # Unmaintained Third Party Components) plus a per-CVE rule id.
    ("pip_audit", "*"): StandardsEntry(
        canonical_cwe="CWE-1104", owasp_top10="A06", asvs_section="V14.2.1",
        nist_ssdf="PW.4.4", category=Category.DEPENDENCIES,
        severity=Severity.HIGH, confidence=Confidence.HIGH,
        short_desc="Known-vulnerable dependency in pinned set.",
        fix_hint="Bump to the fixed version per the advisory. If no fix exists, document the residual risk in `.scignore.yaml` with an expires date.",
    ),

    # ----- npm audit -------------------------------------------------------
    ("npm_audit", "*"): StandardsEntry(
        canonical_cwe="CWE-1104", owasp_top10="A06", asvs_section="V14.2.1",
        nist_ssdf="PW.4.4", category=Category.DEPENDENCIES,
        severity=Severity.HIGH, confidence=Confidence.HIGH,
        short_desc="Known-vulnerable npm dependency.",
        fix_hint="`npm audit fix` is often safe for patch-level bumps but can downgrade majors. Inspect the suggested fix before applying; for downgrades, track upstream.",
    ),

    # ----- Gitleaks --------------------------------------------------------
    # Source: https://github.com/gitleaks/gitleaks
    ("gitleaks", "*"): StandardsEntry(
        canonical_cwe="CWE-798", owasp_top10="A07", asvs_section="V2.10.1",
        nist_ssdf="PS.1.1", category=Category.SECRETS,
        severity=Severity.CRITICAL, confidence=Confidence.HIGH,
        short_desc="Hardcoded secret detected.",
        fix_hint="Rotate the secret immediately. Move to an env var / secret manager. Run `git filter-repo` to scrub history if it's been pushed publicly.",
    ),

    # ----- TruffleHog ------------------------------------------------------
    ("trufflehog", "*"): StandardsEntry(
        canonical_cwe="CWE-798", owasp_top10="A07", asvs_section="V2.10.1",
        nist_ssdf="PS.1.1", category=Category.SECRETS,
        severity=Severity.CRITICAL, confidence=Confidence.HIGH,
        short_desc="Verified secret detected.",
        fix_hint="Same as Gitleaks: rotate, move to env / secret manager, scrub history if leaked publicly.",
    ),

    # ----- Built-in regex rules -------------------------------------------
    ("builtin_rules", "sca.python.eval"): StandardsEntry(
        canonical_cwe="CWE-95", owasp_top10="A03", asvs_section="V5.2.4",
        nist_ssdf="PW.5.1", category=Category.CODE_VULNERABILITIES,
        severity=Severity.HIGH, confidence=Confidence.MEDIUM,
        short_desc="eval()/exec() on non-literal input.",
        fix_hint="Eliminate eval. Use ast.literal_eval for safe data, or a typed registry for dispatch.",
    ),
    ("builtin_rules", "sca.python.yaml.unsafe_load"): StandardsEntry(
        canonical_cwe="CWE-502", owasp_top10="A08", asvs_section="V5.5.2",
        nist_ssdf="PW.5.1", category=Category.CODE_VULNERABILITIES,
        severity=Severity.HIGH, confidence=Confidence.HIGH,
        short_desc="yaml.load() without SafeLoader.",
        fix_hint="Use yaml.safe_load() or yaml.load(stream, Loader=yaml.SafeLoader).",
    ),
    ("builtin_rules", "sca.python.requests.verify_false"): StandardsEntry(
        canonical_cwe="CWE-295", owasp_top10="A07", asvs_section="V9.2.1",
        nist_ssdf="PW.4.1", category=Category.CRYPTO,
        severity=Severity.HIGH, confidence=Confidence.HIGH,
        short_desc="requests.* called with verify=False.",
        fix_hint="Remove verify=False. Pass the trusted CA bundle if the upstream cert is self-signed.",
    ),
    ("builtin_rules", "sca.python.fstring_sql"): StandardsEntry(
        canonical_cwe="CWE-89", owasp_top10="A03", asvs_section="V5.3.5",
        nist_ssdf="PW.5.1", category=Category.CODE_VULNERABILITIES,
        severity=Severity.HIGH, confidence=Confidence.MEDIUM,
        short_desc="f-string SQL — interpolated value in .execute()/.executemany().",
        fix_hint="Parameterize: `await conn.execute('... WHERE id = $1', value)` instead of f-string.",
    ),
    ("builtin_rules", "sca.python.subprocess.shell_true"): StandardsEntry(
        canonical_cwe="CWE-78", owasp_top10="A03", asvs_section="V5.3.8",
        nist_ssdf="PW.5.1", category=Category.CODE_VULNERABILITIES,
        severity=Severity.HIGH, confidence=Confidence.HIGH,
        short_desc="subprocess.* with shell=True and non-literal command.",
        fix_hint="Pass argv as a list (e.g. ['git', 'log', '-n', '5']) and use shell=False.",
    ),
    ("builtin_rules", "sca.python.hashlib.md5_sha1_security"): StandardsEntry(
        canonical_cwe="CWE-327", owasp_top10="A02", asvs_section="V6.2.5",
        nist_ssdf="PW.4.1", category=Category.CRYPTO,
        severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
        short_desc="MD5/SHA-1 in a non-test, non-checksum path.",
        fix_hint="Use SHA-256 or BLAKE2. For password hashing, use Argon2id (via argon2-cffi or passlib).",
    ),
    ("builtin_rules", "sca.web.dangerously_set_inner_html"): StandardsEntry(
        canonical_cwe="CWE-79", owasp_top10="A03", asvs_section="V5.3.3",
        nist_ssdf="PW.5.1", category=Category.CODE_VULNERABILITIES,
        severity=Severity.HIGH, confidence=Confidence.LOW,
        short_desc="React dangerouslySetInnerHTML with non-literal input.",
        fix_hint="Render via React text nodes. If raw HTML is required, sanitize with DOMPurify and document the trust source inline.",
    ),
    ("builtin_rules", "sca.web.cors_wildcard"): StandardsEntry(
        canonical_cwe="CWE-942", owasp_top10="A05", asvs_section="V14.5.3",
        nist_ssdf="PW.5.1", category=Category.CODE_VULNERABILITIES,
        severity=Severity.HIGH, confidence=Confidence.HIGH,
        short_desc="CORS Access-Control-Allow-Origin: * with credentials allowed.",
        fix_hint="Scope Allow-Origin to a specific allowlist when credentials are in use. '*' + credentials is forbidden by spec.",
    ),
    ("builtin_rules", "sca.shell.curl_pipe_sh"): StandardsEntry(
        canonical_cwe="CWE-78", owasp_top10="A03", asvs_section="V5.3.8",
        nist_ssdf="PW.4.4", category=Category.SUPPLY_CHAIN,
        severity=Severity.MEDIUM, confidence=Confidence.HIGH,
        short_desc="curl | sh / wget | bash — opaque remote-script execution.",
        fix_hint="Pin a checksum or use a package manager. If you must download a script, verify a SHA before executing.",
    ),
}


def lookup(scanner: str, rule_id: str) -> Optional[StandardsEntry]:
    """Resolve (scanner, rule_id) → StandardsEntry, with wildcard fallback.

    Order: exact match → (scanner, "*") wildcard → None.
    """
    exact = _MAP.get((scanner.lower(), rule_id))
    if exact is not None:
        return exact
    return _MAP.get((scanner.lower(), "*"))


def is_top25(canonical_cwe: Optional[str]) -> bool:
    """Is this CWE on the MITRE Top 25 (2025) list? Used for scoring boost."""
    return canonical_cwe is not None and canonical_cwe in CWE_TOP25_2025


def cwe_url(canonical_cwe: str) -> str:
    """Cite a CWE id — e.g. 'CWE-89' → MITRE definition URL."""
    num = canonical_cwe.split("-", 1)[1] if "-" in canonical_cwe else canonical_cwe
    return f"https://cwe.mitre.org/data/definitions/{num}.html"


def owasp_url(owasp_id: str) -> str:
    """OWASP Top 10 bucket id → URL."""
    return OWASP_TOP10_2021_URL


def owasp_label(owasp_id: str) -> str:
    """'A03' → 'A03:2021-Injection'. Returns the id unchanged if not mapped."""
    bucket = owasp_id.split(":", 1)[0] if ":" in owasp_id else owasp_id
    return OWASP_TOP10_2021.get(bucket, owasp_id)
