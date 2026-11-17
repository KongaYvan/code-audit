"""Exemple de code PROPRE : code-audit ne doit rien relever ici."""

import hashlib
import os
import subprocess

import yaml


def run(args):
    # Pas de shell, arguments sous forme de liste.
    subprocess.run(["ls", *args], shell=False, check=True)


def load_config(blob):
    return yaml.safe_load(blob)


def get_password():
    # Le secret vient de l'environnement, pas du code.
    return os.environ["APP_PASSWORD"]


def fingerprint(value):
    return hashlib.sha256(value.encode()).hexdigest()
