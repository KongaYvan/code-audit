"""Tests de l'analyse AST du code Python."""

from codeaudit.pyast import analyze_python


def _rules(code):
    return {f.rule for f in analyze_python(code, "f.py")}


def test_eval_and_exec():
    assert "PY_EVAL" in _rules("eval(x)")
    assert "PY_EXEC" in _rules("exec(x)")


def test_os_system():
    assert "PY_OS_SYSTEM" in _rules("import os\nos.system('ls')")


def test_shell_true():
    assert "PY_SHELL_TRUE" in _rules("import subprocess\nsubprocess.run('ls', shell=True)")


def test_shell_false_not_flagged():
    assert "PY_SHELL_TRUE" not in _rules("import subprocess\nsubprocess.run(['ls'], shell=False)")


def test_pickle_loads():
    assert "PY_PICKLE" in _rules("import pickle\npickle.loads(b)")


def test_yaml_load_unsafe():
    assert "PY_YAML_LOAD" in _rules("import yaml\nyaml.load(s)")


def test_yaml_safe_load_not_flagged():
    assert "PY_YAML_LOAD" not in _rules("import yaml\nyaml.safe_load(s)")


def test_yaml_load_with_safeloader_not_flagged():
    code = "import yaml\nyaml.load(s, Loader=yaml.SafeLoader)"
    assert "PY_YAML_LOAD" not in _rules(code)


def test_weak_hash():
    assert "PY_WEAK_HASH" in _rules("import hashlib\nhashlib.md5(b)")


def test_strong_hash_not_flagged():
    assert "PY_WEAK_HASH" not in _rules("import hashlib\nhashlib.sha256(b)")


def test_verify_false():
    assert "PY_VERIFY_FALSE" in _rules("import requests\nrequests.get(u, verify=False)")


def test_debug_true():
    assert "PY_DEBUG_TRUE" in _rules("app.run(debug=True)")


def test_clean_code_no_findings():
    code = (
        "import subprocess, hashlib, os\n"
        "subprocess.run(['ls'], check=True)\n"
        "hashlib.sha256(b'x')\n"
        "os.environ['K']\n"
    )
    assert _rules(code) == set()


def test_syntax_error_reports_parse_error():
    assert "PY_PARSE_ERROR" in _rules("def (:\n  pass")
