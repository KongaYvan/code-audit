"""Objet commun à tous les détecteurs : un problème relevé dans le code."""

from __future__ import annotations

from dataclasses import dataclass

# Gravités, de la plus faible à la plus forte.
SEVERITIES = ("info", "warn", "danger")


@dataclass(frozen=True)
class Finding:
    """Un problème de sécurité relevé à un endroit précis du code."""

    rule: str        # identifiant court, ex. "PY_EVAL", "SECRET_AWS_KEY"
    message: str     # explication lisible
    severity: str    # "info" | "warn" | "danger"
    path: str        # chemin du fichier (relatif à la racine analysée)
    line: int        # numéro de ligne (1 = première ligne ; 0 si inconnu)

    def sort_key(self) -> tuple:
        """Pour trier : plus grave d'abord, puis par fichier et ligne."""
        rank = SEVERITIES.index(self.severity) if self.severity in SEVERITIES else -1
        return (-rank, self.path, self.line)
