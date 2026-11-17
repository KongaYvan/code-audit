"""Phase 4 — verdict global à partir des problèmes relevés.

Principe transparent (comme mail-verifier) : chaque problème vaut des points
selon sa gravité ; le total, borné à 100, donne un niveau. Objectif : une
conclusion lisible en un coup d'œil, défendable point par point.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .finding import Finding

# Points par gravité.
_POINTS = {"danger": 40, "warn": 10, "info": 2}

# Seuils de niveau (score 0..100).
_LEVELS = [
    (40, "CRITIQUE", "Failles graves dans le code : à corriger avant toute mise en service."),
    (10, "À CORRIGER", "Points de sécurité à reprendre."),
    (1, "À SURVEILLER", "Quelques signaux mineurs à vérifier."),
    (0, "RAS", "Aucun problème relevé (absence de preuve n'est pas preuve d'absence)."),
]


@dataclass
class Verdict:
    score: int = 0
    level: str = "RAS"
    advice: str = ""
    counts: dict[str, int] = field(default_factory=lambda: {"danger": 0, "warn": 0, "info": 0})


def compute_verdict(findings: list[Finding]) -> Verdict:
    counts = {"danger": 0, "warn": 0, "info": 0}
    total = 0
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
        total += _POINTS.get(f.severity, 0)

    score = min(100, total)
    for threshold, level, advice in _LEVELS:
        if score >= threshold:
            return Verdict(score=score, level=level, advice=advice, counts=counts)
    return Verdict(score=score, counts=counts)
