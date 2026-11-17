"""Exemple de code VOLONTAIREMENT vulnérable (pour tester code-audit).
Ne jamais écrire du code comme ceci en vrai. Les secrets sont factices."""

import hashlib
import os
import pickle
import subprocess

import yaml

# --- Secrets en dur (à détecter en phase 2) ---
PASSWORD = "SuperSecret123"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"      # clé d'exemple AWS (factice)
GOOGLE_API_KEY = "AIzaSyB1234567890abcdefghijklmnopqrstuv"  # factice
API_TOKEN = "changeme"                        # placeholder -> ne doit PAS alerter


def run(cmd):
    # --- Exécution dangereuse (à détecter en phase 3) ---
    os.system("ping " + cmd)                  # os.system
    subprocess.run("ls " + cmd, shell=True)   # shell=True


def compute(expr):
    return eval(expr)                          # eval d'une entrée


def load_config(blob):
    data = yaml.load(blob)                     # yaml.load sans SafeLoader
    obj = pickle.loads(blob)                   # désérialisation non sûre
    return data, obj


def fingerprint(value):
    return hashlib.md5(value.encode()).hexdigest()  # crypto faible
