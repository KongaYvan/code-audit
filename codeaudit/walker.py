"""Parcours du dossier à analyser.

Rôle : donner la liste des fichiers texte pertinents, en ignorant les dossiers
techniques (environnements, caches, dépôts) et les fichiers binaires ou trop
gros. Ne juge rien : il prépare le travail des détecteurs.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

# Dossiers à ne jamais analyser (bruit ou non-source).
_SKIP_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "env", "__pycache__",
    "node_modules", ".idea", ".vscode", "dist", "build", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", ".tox", "site-packages", ".cache",
}

# Taille max d'un fichier analysé (octets). Au-delà, on saute (probablement
# des données, pas du code).
_MAX_BYTES = 1_000_000


def iter_files(root: str | Path) -> Iterator[Path]:
    """Génère les chemins des fichiers à analyser sous `root`."""
    root = Path(root)
    if root.is_file():
        yield root
        return
    for path in sorted(root.rglob("*")):
        if path.is_dir():
            continue
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if path.is_file():
            yield path


def read_text(path: Path) -> str | None:
    """Lit un fichier en texte UTF-8. Renvoie None si binaire ou trop gros."""
    try:
        if path.stat().st_size > _MAX_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data:  # octet nul = fichier binaire
        return None
    return data.decode("utf-8", errors="replace")


def is_python(path: Path) -> bool:
    return path.suffix == ".py"
