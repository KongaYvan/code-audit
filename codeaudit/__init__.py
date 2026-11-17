"""code-audit — analyseur de sécurité de code (SAST).

Projet d'Yvan Konga. Outil CLI qui parcourt le dossier d'une application et
repère des failles de sécurité dans le code : secrets en dur (regex, tout
fichier texte) et patterns dangereux du code Python (analyse AST).

Outil d'apprentissage : ne remplace pas Bandit/Semgrep.
"""

__version__ = "0.1.0"
