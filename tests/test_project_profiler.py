"""Unit tests for project profiler and language/framework detection."""

from pathlib import Path
import pytest

from modules.project_profiler import profile_project


def test_profile_empty_project(tmp_path):
    res = profile_project(tmp_path)
    assert res["total_files"] == 0
    assert res["inspected_files"] == 0
    assert res["languages"] == []
    assert res["frameworks"] == []


def test_profile_multi_language_project(tmp_path):
    # Setup files
    (tmp_path / "main.py").write_text("import fastapi\napp = fastapi.FastAPI()\n")
    (tmp_path / "index.js").write_text("console.log('hello');\n")
    (tmp_path / "requirements.txt").write_text("fastapi==0.100.0\nuvicorn\n")
    (tmp_path / "Dockerfile").write_text("FROM python:3.13-slim\n")

    res = profile_project(tmp_path)
    assert res["total_files"] == 4
    assert res["inspected_files"] >= 3
    assert "Python" in res["languages"]
    assert "JavaScript" in res["languages"]
    assert "FastAPI" in res["frameworks"]
    assert "requirements.txt" in res["manifests"]
    assert "Dockerfile" in res["configs"]


def test_profile_ignores_vendor_and_cache(tmp_path):
    # node_modules and .git should be ignored
    node_dir = tmp_path / "node_modules" / "some_pkg"
    node_dir.mkdir(parents=True)
    (node_dir / "index.js").write_text("module.exports = {};")

    (tmp_path / "app.py").write_text("print('root app')")

    res = profile_project(tmp_path)
    assert res["inspected_files"] == 1
    assert res["inspected_file_paths"] == ["app.py"]

