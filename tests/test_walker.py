"""Tests du parcours de dossier."""

from pathlib import Path

from codeaudit.walker import iter_files, is_python, read_text


def test_skips_technical_dirs(tmp_path: Path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("x = 1", encoding="utf-8")
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "b.py").write_text("y = 2", encoding="utf-8")

    found = {p.name for p in iter_files(tmp_path)}
    assert "a.py" in found
    assert "b.py" not in found  # .venv ignoré


def test_read_text_rejects_binary(tmp_path: Path):
    f = tmp_path / "img.bin"
    f.write_bytes(b"\x89PNG\x00\x00binary")
    assert read_text(f) is None


def test_read_text_rejects_too_large(tmp_path: Path):
    f = tmp_path / "big.txt"
    f.write_bytes(b"a" * 2_000_000)
    assert read_text(f) is None


def test_read_text_ok(tmp_path: Path):
    f = tmp_path / "ok.py"
    f.write_text("print('hi')", encoding="utf-8")
    assert read_text(f) == "print('hi')"


def test_is_python():
    assert is_python(Path("a.py")) is True
    assert is_python(Path("a.txt")) is False
