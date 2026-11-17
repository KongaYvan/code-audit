"""Analyse de sécurité du code Python via son AST (arbre syntaxique).

Pourquoi l'AST et pas du texte ? Parce qu'on veut repérer un VRAI appel de
fonction, pas une chaîne qui contient le mot « eval ». `ast.parse` transforme
le code en arbre : on le parcourt et on reconnaît les nœuds dangereux (un appel
`eval(...)`, un `subprocess(..., shell=True)`, etc.) avec leur numéro de ligne.

Limite assumée : on reconnaît les appels par leur nom (`os.system`,
`subprocess.run`, `yaml.load`…). Un alias (`from os import system as s`) peut
échapper à la détection — comme pour tout analyseur simple. À documenter.
"""

from __future__ import annotations

import ast

from .finding import Finding

# Chargeurs YAML considérés comme sûrs.
_SAFE_YAML_LOADERS = {"SafeLoader", "BaseLoader", "CSafeLoader"}


def analyze_python(text: str, path: str) -> list[Finding]:
    """Analyse un source Python. Renvoie la liste des problèmes trouvés."""
    try:
        tree = ast.parse(text, filename=path)
    except SyntaxError as exc:
        return [Finding("PY_PARSE_ERROR", f"Fichier Python non analysable ({exc.msg})",
                        "info", path, exc.lineno or 0)]

    findings: list[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            _check_call(node, path, findings)
    return findings


def _check_call(node: ast.Call, path: str, out: list[Finding]) -> None:
    name = _call_name(node.func)
    line = node.lineno

    def add(rule: str, message: str, severity: str) -> None:
        out.append(Finding(rule, message, severity, path, line))

    # Exécution de code / de commandes
    if name in {"eval", "exec"}:
        add(f"PY_{name.upper()}", f"Appel à {name}() (exécution de code arbitraire)", "danger")
    if name in {"os.system", "os.popen"}:
        add("PY_OS_SYSTEM", f"{name}() (exécution d'une commande shell)", "danger")
    if _has_kw_true(node, "shell"):
        add("PY_SHELL_TRUE", "Appel avec shell=True (injection de commande possible)", "danger")

    # Désérialisation non sûre
    if name in {"pickle.load", "pickle.loads"}:
        add("PY_PICKLE", f"{name}() (désérialisation non sûre)", "danger")
    if name == "yaml.load" and not _yaml_is_safe(node):
        add("PY_YAML_LOAD", "yaml.load() sans SafeLoader (exécution de code possible)", "danger")

    # Crypto faible
    if name in {"hashlib.md5", "hashlib.sha1"}:
        add("PY_WEAK_HASH", f"{name}() : algorithme faible pour un usage de sécurité", "warn")

    # Configuration risquée
    if _has_kw_false(node, "verify"):
        add("PY_VERIFY_FALSE", "verify=False (vérification du certificat TLS désactivée)", "warn")
    if name.endswith(".run") and _has_kw_true(node, "debug"):
        add("PY_DEBUG_TRUE", "debug=True (mode debug : ne jamais activer en production)", "warn")
    if name == "tempfile.mktemp":
        add("PY_MKTEMP", "tempfile.mktemp() (condition de course ; préférer mkstemp)", "warn")


def _call_name(func: ast.expr) -> str:
    """Nom pointé d'un appel : eval, os.system, subprocess.run, yaml.load…"""
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts = [func.attr]
        value = func.value
        while isinstance(value, ast.Attribute):
            parts.append(value.attr)
            value = value.value
        if isinstance(value, ast.Name):
            parts.append(value.id)
        return ".".join(reversed(parts))
    return ""


def _has_kw_true(node: ast.Call, name: str) -> bool:
    return _kw_is(node, name, True)


def _has_kw_false(node: ast.Call, name: str) -> bool:
    return _kw_is(node, name, False)


def _kw_is(node: ast.Call, name: str, expected: bool) -> bool:
    for kw in node.keywords:
        if kw.arg == name and isinstance(kw.value, ast.Constant) and kw.value.value is expected:
            return True
    return False


def _yaml_is_safe(node: ast.Call) -> bool:
    """yaml.load est sûr s'il reçoit Loader=SafeLoader (ou équivalent)."""
    for kw in node.keywords:
        if kw.arg == "Loader":
            loader = _call_name(kw.value) if isinstance(kw.value, (ast.Attribute, ast.Name)) else ""
            return any(loader.endswith(safe) for safe in _SAFE_YAML_LOADERS)
    return False
