"""Mise en forme du rapport (terminal). Le verdict global viendra en phase 4."""

from __future__ import annotations

from .finding import Finding
from .score import Verdict

_MARK = {"info": "·", "warn": "!", "danger": "X"}


def _counts(findings: list[Finding]) -> dict[str, int]:
    c = {"danger": 0, "warn": 0, "info": 0}
    for f in findings:
        c[f.severity] = c.get(f.severity, 0) + 1
    return c


def render_terminal(findings: list[Finding], files_scanned: int,
                    verdict: Verdict | None = None) -> str:
    lines: list[str] = []
    lines.append("=" * 60)
    lines.append("  CODE-AUDIT — rapport")
    lines.append("=" * 60)
    lines.append("")
    if verdict is not None:
        bar = "#" * (verdict.score // 5) + "-" * (20 - verdict.score // 5)
        lines.append(f"VERDICT : {verdict.level}  (risque {verdict.score}/100  [{bar}])")
        lines.append(f"  {verdict.advice}")
        lines.append("")
    c = _counts(findings)
    lines.append(f"Fichiers analysés : {files_scanned}")
    lines.append(f"Problèmes relevés : {len(findings)} "
                 f"({c['danger']} grave(s), {c['warn']} alerte(s), {c['info']} info(s))")
    lines.append("")

    if findings:
        lines.append("— Détail —")
        for f in sorted(findings, key=Finding.sort_key):
            lines.append(f"  [{_MARK.get(f.severity, '?')}] {f.path}:{f.line}  "
                         f"{f.message} ({f.rule})")
    else:
        lines.append("Aucun problème relevé.")
    lines.append("")
    return "\n".join(lines)


def build_json(findings: list[Finding], files_scanned: int,
               verdict: Verdict | None = None) -> dict:
    data: dict = {}
    if verdict is not None:
        data["verdict"] = {
            "level": verdict.level,
            "risk_score": verdict.score,
            "advice": verdict.advice,
        }
    data.update({
        "files_scanned": files_scanned,
        "counts": _counts(findings),
        "findings": [
            {"rule": f.rule, "severity": f.severity, "message": f.message,
             "path": f.path, "line": f.line}
            for f in sorted(findings, key=Finding.sort_key)
        ],
    })
    return data
