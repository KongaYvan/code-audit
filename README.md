# code-audit — analyseur de sécurité de code (SAST)

Outil Python en ligne de commande qui parcourt le **dossier d'une application**
et repère des **failles de sécurité dans le code** : secrets en dur et patterns
dangereux du code Python. Il produit un **verdict** et la liste des problèmes
(gravité, fichier, ligne).

Projet personnel d'apprentissage (sécurité applicative / DevSecOps). Le cœur
n'utilise **que la bibliothèque standard Python** — aucune dépendance à installer.

> ⚠️ **Outil pédagogique.** Il ne remplace pas [Bandit](https://bandit.readthedocs.io)
> ni Semgrep : il couvre les failles les plus courantes avec un code lisible,
> pour *comprendre* ce que ces outils font sous le capot. Voir
> [COMPARAISON-BANDIT.md](COMPARAISON-BANDIT.md).

## Ce qu'il détecte

| Famille | Exemples | Technique |
|---|---|---|
| **Secrets en dur** | clé privée, clé AWS (`AKIA…`), clé d'API Google, token Slack, `password = "..."` | regex (tout fichier texte) |
| **Exécution dangereuse** | `eval`, `exec`, `os.system`, `subprocess(..., shell=True)` | AST Python |
| **Désérialisation non sûre** | `pickle.loads`, `yaml.load` sans `SafeLoader` | AST Python |
| **Crypto faible** | `hashlib.md5`, `hashlib.sha1` | AST Python |
| **Config risquée** | `verify=False`, `app.run(debug=True)`, `tempfile.mktemp` | AST Python |

Chaque problème est un **drapeau** (`danger` / `warn` / `info`) avec sa position.
Le **verdict global** (`CRITIQUE` / `À CORRIGER` / `À SURVEILLER` / `RAS`) additionne
des points par gravité — transparent, défendable point par point.

## Installation

Aucune dépendance runtime. Python 3.10+ suffit.

```bash
git clone https://github.com/KongaYvan/code-audit
cd code-audit
python main.py <dossier à analyser>
```

## Utilisation

```bash
python main.py samples/vuln_app          # rapport lisible
python main.py mon_projet/ --json        # sortie JSON (automatisable)
```

### Exemple de sortie

```
$ python main.py samples/vuln_app

VERDICT : CRITIQUE  (risque 100/100  [####################])
  Failles graves dans le code : à corriger avant toute mise en service.

Fichiers analysés : 1
Problèmes relevés : 9 (7 grave(s), 2 alerte(s), 0 info(s))

— Détail —
  [X] app.py:13  Clé d'accès AWS en dur (SECRET_AWS_KEY)
  [X] app.py:14  Clé d'API Google en dur (SECRET_GOOGLE_API)
  [X] app.py:20  os.system() (exécution d'une commande shell) (PY_OS_SYSTEM)
  [X] app.py:21  Appel avec shell=True (injection de commande possible) (PY_SHELL_TRUE)
  [X] app.py:25  Appel à eval() (exécution de code arbitraire) (PY_EVAL)
  [X] app.py:29  yaml.load() sans SafeLoader (exécution de code possible) (PY_YAML_LOAD)
  [X] app.py:30  pickle.loads() (désérialisation non sûre) (PY_PICKLE)
  [!] app.py:12  Mot de passe / clé / token en dur (valeur littérale) (SECRET_GENERIC)
  [!] app.py:35  hashlib.md5() : algorithme faible pour un usage de sécurité (PY_WEAK_HASH)
```

## Architecture

```
codeaudit/
  finding.py    objet Finding (règle, gravité, fichier, ligne, message)
  walker.py     parcours du dossier (ignore .venv/.git… et les binaires)
  secrets.py    détection de secrets en dur (regex)
  pyast.py      analyse AST du code Python (appels dangereux)
  score.py      verdict global (points par gravité)
  report.py     mise en forme terminal + JSON
main.py         point d'entrée CLI
samples/        code volontairement troué + code propre
tests/          33 tests pytest
```

**Pourquoi l'AST et pas une recherche de texte ?** Pour repérer un *vrai appel*
de fonction (`eval(...)`), pas le mot « eval » dans un commentaire ou une chaîne.
On lit la structure du code, pas sa surface.

## Tests

```bash
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.venv\Scripts\python.exe -m pytest
```

Un test vérifie qu'un **code propre ne déclenche aucun drapeau** (contrôle des
faux positifs), aussi important que de détecter les vraies failles.

## Limites connues (assumées)

- **Détection par nom d'appel.** On reconnaît `os.system`, `yaml.load`, etc. Un
  alias (`from os import system as s`) peut échapper à l'analyse — vrai de tout
  analyseur simple.
- **AST = Python uniquement.** Les autres langages ne bénéficient que de la
  détection de secrets (texte). Multi-langage : piste future.
- **Listes non exhaustives** (motifs de secrets, règles AST) : volontairement
  courtes et lisibles, à étendre au besoin.
- **Pas un remplaçant de Bandit/Semgrep** : voir la comparaison honnête dans
  [COMPARAISON-BANDIT.md](COMPARAISON-BANDIT.md).

## Pistes d'amélioration

- Plus de règles AST (injection SQL par suivi de variable, requêtes non sûres…).
- Support multi-langage (JavaScript, PHP) via d'autres parseurs.
- Détection de secrets par entropie (chaînes aléatoires).
- Intégration CI (code de sortie non nul si verdict ≥ seuil).

---

Projet réalisé dans un cadre d'apprentissage. Le dossier `samples/vuln_app`
contient **volontairement** du code vulnérable et des secrets **factices**
(ex. la clé d'exemple publique d'AWS) : ce sont des cas de test, pas de vraies
données.
