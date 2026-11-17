"""Tests de la détection de secrets."""

from codeaudit.secrets import scan_text


def _rules(text):
    return {f.rule for f in scan_text(text, "f.txt")}


def test_aws_key_detected():
    assert "SECRET_AWS_KEY" in _rules('key = "AKIAIOSFODNN7EXAMPLE"')


def test_google_api_detected():
    assert "SECRET_GOOGLE_API" in _rules('k = "AIzaSyB1234567890abcdefghijklmnopqrstuv"')


def test_private_key_detected():
    assert "SECRET_PRIVATE_KEY" in _rules("-----BEGIN RSA PRIVATE KEY-----")


def test_generic_password_detected():
    assert "SECRET_GENERIC" in _rules('password = "hunter2xyz"')


def test_placeholder_not_flagged():
    # Valeur factice -> pas d'alerte.
    assert "SECRET_GENERIC" not in _rules('password = "changeme"')
    assert "SECRET_GENERIC" not in _rules('token = "${TOKEN}"')


def test_env_var_not_flagged():
    # Secret lu dans l'environnement : aucune valeur littérale -> rien.
    assert _rules('password = os.environ["APP_PASSWORD"]') == set()


def test_line_number_reported():
    findings = scan_text('x = 1\npassword = "realsecret1"', "f.py")
    assert findings[0].line == 2
