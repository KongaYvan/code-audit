"""Test d'intégration sur les dossiers d'exemple (via le CLI analyze())."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from main import analyze  # noqa: E402

SAMPLES = ROOT / "samples"


def test_vuln_app_flags_key_rules():
    findings, scanned = analyze(str(SAMPLES / "vuln_app"))
    rules = {f.rule for f in findings}
    assert scanned >= 1
    for expected in ("SECRET_AWS_KEY", "PY_EVAL", "PY_SHELL_TRUE",
                     "PY_PICKLE", "PY_YAML_LOAD"):
        assert expected in rules, expected


def test_clean_app_is_empty():
    findings, scanned = analyze(str(SAMPLES / "clean_app"))
    assert scanned >= 1
    assert findings == []
