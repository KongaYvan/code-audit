"""Détection de secrets en dur (regex), sur n'importe quel fichier texte.

Un « secret » est une donnée sensible écrite directement dans le code : mot de
passe, clé d'API, token, clé privée. On signale la ligne, jamais la valeur
complète (on tronque), pour ne pas recopier le secret dans le rapport.
"""

from __future__ import annotations

import re
from pathlib import Path

from .finding import Finding

# Chaque règle : (id, gravité, message, expression régulière compilée).
_RULES: list[tuple[str, str, str, re.Pattern]] = [
    ("SECRET_PRIVATE_KEY", "danger", "Clé privée en dur",
     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("SECRET_AWS_KEY", "danger", "Clé d'accès AWS en dur",
     re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("SECRET_GOOGLE_API", "danger", "Clé d'API Google en dur",
     re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("SECRET_SLACK_TOKEN", "danger", "Token Slack en dur",
     re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("SECRET_GENERIC", "warn", "Mot de passe / clé / token en dur (valeur littérale)",
     re.compile(r"""(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|token|access[_-]?key)\b"""
                r"""\s*[:=]\s*(['"])(?P<val>[^'"]{4,})\1""")),
]

# Valeurs manifestement factices : on n'alerte pas dessus (réduction de bruit).
_PLACEHOLDERS = re.compile(
    r"(?i)^(x+|changeme|placeholder|your[_-]?\w+|examples?|dummy|test|todo|none|null|\.{3,}|\*+)$")


def scan_text(text: str, path: str) -> list[Finding]:
    findings: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for rule, severity, message, pattern in _RULES:
            m = pattern.search(line)
            if not m:
                continue
            # Pour la règle générique, ignorer les valeurs factices.
            if rule == "SECRET_GENERIC":
                val = m.group("val")
                if _PLACEHOLDERS.match(val.strip()) or val.strip().startswith("${"):
                    continue
            findings.append(Finding(rule=rule, message=message,
                                    severity=severity, path=path, line=lineno))
    return findings


def scan_file(text: str, path: Path, root: Path) -> list[Finding]:
    rel = _relative(path, root)
    return scan_text(text, rel)


def _relative(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)
