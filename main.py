"""Point d'entrée CLI de code-audit.

Usage :
    python main.py chemin/du/dossier
    python main.py chemin/du/dossier --json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from codeaudit import pyast, secrets, walker
from codeaudit.finding import Finding
from codeaudit.report import build_json, render_terminal
from codeaudit.score import compute_verdict


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="code-audit",
        description="Analyse un dossier de code à la recherche de failles de sécurité.",
    )
    p.add_argument("path", help="dossier (ou fichier) à analyser")
    p.add_argument("--json", action="store_true", help="sortie JSON")
    return p


def analyze(root: str) -> tuple[list[Finding], int]:
    """Parcourt `root` et renvoie (findings, nombre de fichiers analysés)."""
    root_path = Path(root)
    base = root_path if root_path.is_dir() else root_path.parent
    findings: list[Finding] = []
    files_scanned = 0

    for path in walker.iter_files(root_path):
        text = walker.read_text(path)
        if text is None:
            continue
        files_scanned += 1
        rel = str(path.relative_to(base)) if _under(path, base) else str(path)
        findings.extend(secrets.scan_text(text, rel))
        if walker.is_python(path):
            findings.extend(pyast.analyze_python(text, rel))
    return findings, files_scanned


def _under(path: Path, base: Path) -> bool:
    try:
        path.relative_to(base)
        return True
    except ValueError:
        return False


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

    args = build_parser().parse_args(argv)
    if not Path(args.path).exists():
        print(f"Erreur : chemin introuvable : {args.path}", file=sys.stderr)
        return 2

    findings, files_scanned = analyze(args.path)
    verdict = compute_verdict(findings)
    if args.json:
        print(json.dumps(build_json(findings, files_scanned, verdict),
                         ensure_ascii=False, indent=2))
    else:
        print(render_terminal(findings, files_scanned, verdict))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
