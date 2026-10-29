"""Unit tests for archive validation and safe extraction."""

import io
from pathlib import Path
import tempfile
import zipfile
import pytest

from modules.archive_handler import cleanup_directory, extract_archive_safely, is_path_safe


def test_is_path_safe():
    base = Path("/safe/workspace")
    assert is_path_safe(base, base / "subdir" / "file.py") is True
    assert is_path_safe(base, base / ".." / "escaped.py") is False


def test_safe_zip_extraction(tmp_path):
    # Create valid in-memory ZIP
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as zf:
        zf.writestr("app.py", "print('hello world')")
        zf.writestr("src/util.py", "def util(): pass")

    dest = tmp_path / "extracted"
    success, err, meta = extract_archive_safely(bio, dest)

    assert success is True
    assert err == ""
    assert meta["files_extracted"] == 2
    assert (dest / "app.py").exists()
    assert (dest / "src" / "util.py").exists()
    assert (dest / "app.py").read_text() == "print('hello world')"


def test_path_traversal_zip_slip_rejection(tmp_path):
    # Craft malicious zip entry with traversal
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as zf:
        zf.writestr("../evil.py", "evil_code()")

    dest = tmp_path / "extracted_slip"
    success, err, meta = extract_archive_safely(bio, dest)

    assert success is False
    assert "Path traversal detected" in err
    assert not (dest / "evil.py").exists()


def test_corrupted_zip_handling(tmp_path):
    bio = io.BytesIO(b"Not a valid zip content")
    dest = tmp_path / "corrupt_dest"
    success, err, meta = extract_archive_safely(bio, dest)

    assert success is False
    assert "corrupted" in err.lower() or "not a valid zip" in err.lower()


def test_empty_zip_handling(tmp_path):
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as zf:
        pass  # empty

    dest = tmp_path / "empty_dest"
    success, err, meta = extract_archive_safely(bio, dest)

    assert success is True
    assert meta["files_extracted"] == 0


def test_cleanup_directory(tmp_path):
    sub = tmp_path / "to_delete"
    sub.mkdir()
    (sub / "test.txt").write_text("temp")
    assert sub.exists()

    cleanup_directory(sub)
    assert not sub.exists()

