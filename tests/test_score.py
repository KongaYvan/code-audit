"""Tests du verdict global."""

from codeaudit.finding import Finding
from codeaudit.score import compute_verdict


def _f(severity):
    return Finding("R", "msg", severity, "f.py", 1)


def test_no_findings_is_ras():
    v = compute_verdict([])
    assert v.level == "RAS"
    assert v.score == 0


def test_single_info_a_surveiller():
    v = compute_verdict([_f("info")])
    assert v.level == "À SURVEILLER"
    assert v.score == 2


def test_single_warn_a_corriger():
    v = compute_verdict([_f("warn")])
    assert v.level == "À CORRIGER"
    assert v.score == 10


def test_one_danger_critique():
    v = compute_verdict([_f("danger")])
    assert v.level == "CRITIQUE"
    assert v.score == 40


def test_score_capped():
    v = compute_verdict([_f("danger")] * 5)
    assert v.score == 100
    assert v.counts["danger"] == 5
