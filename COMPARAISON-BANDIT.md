# Comparaison avec Bandit

Bandit est l'analyseur de sécurité Python de référence (OpenStack / PyCQA).
On a fait tourner les deux outils sur le même fichier troué
(`samples/vuln_app/app.py`) pour situer code-audit **honnêtement**.

## Résultat brut

| Problème | Ligne | code-audit | Bandit |
|---|---|:---:|:---:|
| Mot de passe en dur (`SuperSecret123`) | 12 | ✅ | ✅ (B105) |
| **Clé AWS en dur** | 13 | ✅ | ❌ |
| **Clé d'API Google en dur** | 14 | ✅ | ❌ |
| Placeholder `changeme` | 15 | ❌ *(filtré)* | ✅ (B105) |
| `os.system(...)` | 20 | ✅ | ✅ (B605) |
| `subprocess(..., shell=True)` | 21 | ✅ | ✅ (B602) |
| `eval(...)` | 25 | ✅ | ✅ (B307) |
| `yaml.load(...)` sans SafeLoader | 29 | ✅ | ✅ (B506) |
| `pickle.loads(...)` | 30 | ✅ | ✅ (B301) |
| `hashlib.md5(...)` | 35 | ✅ | ✅ (B324) |
| Import de `pickle` | 6 | ❌ | ✅ (B403) |
| Import de `subprocess` | 7 | ❌ | ✅ (B404) |

## Lecture

**Les 7 détections communes** (mot de passe, os.system, shell=True, eval,
yaml.load, pickle.loads, md5) montrent que le cœur de code-audit est aligné
sur l'outil de référence.

**Ce que code-audit trouve et pas Bandit** : les **secrets « cloud »** (clé
AWS, clé d'API Google). Bandit, par défaut, ne cherche pas ces motifs précis ;
code-audit a des expressions dédiées.

**Ce que Bandit trouve et pas code-audit**, par choix de conception :
- **les imports** de `pickle` / `subprocess` (B403/B404) : importer un module
  n'est pas en soi une faille ; code-audit alerte sur l'**appel** dangereux, pas
  sur l'import, pour réduire le bruit ;
- le placeholder **`changeme`** : code-audit filtre volontairement les valeurs
  manifestement factices (moins de faux positifs), là où Bandit signale toute
  chaîne qui ressemble à un mot de passe.

## Conclusion honnête

code-audit **ne remplace pas Bandit** : Bandit couvre beaucoup plus de règles
(injection SQL, désérialisation XML, requêtes non sécurisées, etc.) et gère les
imports. code-audit est un outil **d'apprentissage** qui :
- couvre les failles les plus courantes avec un code lisible et documenté,
- ajoute une détection de secrets cloud que Bandit n'a pas par défaut,
- fait moins de bruit sur les valeurs factices.

Le bon réflexe en production : **utiliser Bandit** (voire Semgrep), et se servir
de code-audit pour *comprendre* ce que ces outils font sous le capot.

> Pour reproduire : `.venv\Scripts\python.exe -m bandit -r samples/vuln_app`
