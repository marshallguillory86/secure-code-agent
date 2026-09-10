"""Built-in regex rules — true positives + at least one false-positive case
per rule."""

from secure_code_audit.config import Config
from secure_code_audit.scanners.builtin_rules import BuiltinRulesScanner


def _write(tmp_path, name, content):
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


def _run(tmp_path):
    scanner = BuiltinRulesScanner()
    cfg = Config()
    return scanner.scan(tmp_path, cfg).findings


# --- eval / exec ----------------------------------------------------------


def test_eval_on_variable_flagged(tmp_path):
    _write(tmp_path, "bad.py", "def go(x): return eval(x)\n")
    findings = _run(tmp_path)
    assert any(f.rule_id == "sca.python.eval" for f in findings)


def test_eval_on_string_literal_not_flagged(tmp_path):
    _write(tmp_path, "ok.py", "eval('1 + 1')\n")
    findings = _run(tmp_path)
    assert not any(f.rule_id == "sca.python.eval" for f in findings)


# --- yaml.load ------------------------------------------------------------


def test_yaml_load_without_safeloader_flagged(tmp_path):
    _write(tmp_path, "y.py", "import yaml\nyaml.load(open('x'))\n")
    findings = _run(tmp_path)
    assert any(f.rule_id == "sca.python.yaml.unsafe_load" for f in findings)


def test_yaml_safe_load_not_flagged(tmp_path):
    _write(tmp_path, "y2.py", "import yaml\nyaml.safe_load(open('x'))\n")
    findings = _run(tmp_path)
    assert not any(f.rule_id == "sca.python.yaml.unsafe_load" for f in findings)


# --- requests verify=False -----------------------------------------------


def test_requests_verify_false_flagged(tmp_path):
    _write(tmp_path, "r.py", "import requests\nrequests.get(u, verify=False)\n")
    findings = _run(tmp_path)
    assert any(f.rule_id == "sca.python.requests.verify_false" for f in findings)


# --- subprocess shell=True ------------------------------------------------


def test_subprocess_shell_true_flagged(tmp_path):
    _write(tmp_path, "s.py", "import subprocess\nsubprocess.run(cmd, shell=True)\n")
    findings = _run(tmp_path)
    assert any(f.rule_id == "sca.python.subprocess.shell_true" for f in findings)


def test_subprocess_shell_false_not_flagged(tmp_path):
    _write(tmp_path, "s2.py", "import subprocess\nsubprocess.run(['git', 'log'])\n")
    findings = _run(tmp_path)
    assert not any(f.rule_id == "sca.python.subprocess.shell_true" for f in findings)


# --- f-string SQL ---------------------------------------------------------


def test_fstring_sql_flagged(tmp_path):
    _write(tmp_path, "q.py", "uid = 5\ncursor.execute(f'SELECT * FROM users WHERE id = {uid}')\n")
    findings = _run(tmp_path)
    assert any(f.rule_id == "sca.python.fstring_sql" for f in findings)


def test_parameterized_sql_not_flagged(tmp_path):
    _write(tmp_path, "q2.py", "cursor.execute('SELECT * FROM users WHERE id = $1', uid)\n")
    findings = _run(tmp_path)
    assert not any(f.rule_id == "sca.python.fstring_sql" for f in findings)


# --- md5 / sha1 -----------------------------------------------------------


def test_md5_without_usedforsecurity_flagged(tmp_path):
    _write(tmp_path, "h.py", "import hashlib\nhashlib.md5(data).hexdigest()\n")
    findings = _run(tmp_path)
    assert any(f.rule_id == "sca.python.hashlib.md5_sha1_security" for f in findings)


def test_md5_usedforsecurity_false_not_flagged(tmp_path):
    _write(
        tmp_path, "h2.py", "import hashlib\nhashlib.md5(data, usedforsecurity=False).hexdigest()\n"
    )
    findings = _run(tmp_path)
    assert not any(f.rule_id == "sca.python.hashlib.md5_sha1_security" for f in findings)


# --- React dangerouslySetInnerHTML ---------------------------------------


def test_dangerously_set_inner_html_flagged(tmp_path):
    _write(
        tmp_path, "Foo.tsx", "const x = <div dangerouslySetInnerHTML={{__html: untrusted}} />;\n"
    )
    findings = _run(tmp_path)
    assert any(f.rule_id == "sca.web.dangerously_set_inner_html" for f in findings)


# --- finding metadata is populated from standards map ---------------------


def test_finding_carries_cwe_owasp_asvs(tmp_path):
    _write(tmp_path, "h.py", "import hashlib\nhashlib.md5(b'').hexdigest()\n")
    findings = _run(tmp_path)
    hits = [f for f in findings if f.rule_id == "sca.python.hashlib.md5_sha1_security"]
    assert hits
    assert hits[0].canonical_cwe == "CWE-327"
    assert hits[0].owasp_top10 == "A02"
    assert hits[0].asvs_section is not None
    assert hits[0].nist_ssdf is not None
    assert hits[0].category.value == "crypto"


def test_a_method_named_eval_is_not_arbitrary_code_execution(tmp_path):
    """`sca.python.eval` matched vocabulary rather than risk.

    The pattern used `\\b`, which matches after a dot, so `self.eval(` and
    `def eval(` both fired. Measured against Django: 28 of its 35 hits were in
    `django/template/smartif.py`, which implements the template `if` parser
    and gives its operator nodes an `eval` method. Those 35 findings were the
    third-largest contributor to Django scoring F, and every one of them was
    ours and wrong.

    A tool that penalises a project for naming a method `eval` is measuring
    the wrong thing, and it is the kind of false positive that teaches people
    to stop reading the report.
    """
    (tmp_path / "parser.py").write_text(
        "class Op:\n"
        "    def eval(self, context):\n"
        "        return self.value\n"
        "\n"
        "def render(node, ctx):\n"
        "    return node.eval(ctx)\n",
        encoding="utf-8",
    )

    findings = _run(tmp_path)

    assert [f.rule_id for f in findings if f.rule_id == "sca.python.eval"] == []


def test_real_eval_and_exec_are_still_caught(tmp_path):
    """The narrowing must not buy quiet by missing the actual defect."""
    (tmp_path / "danger.py").write_text(
        "def run(user_input):\n    eval(user_input)\n    exec(user_input)\n",
        encoding="utf-8",
    )

    findings = _run(tmp_path)

    assert len([f for f in findings if f.rule_id == "sca.python.eval"]) == 2
