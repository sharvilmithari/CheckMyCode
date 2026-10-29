"""Unit tests for Docker, Compose, and environment configuration checks."""

from pathlib import Path
import pytest

from modules.configuration_scanner import (
    scan_docker_compose,
    scan_dockerfile,
    scan_environment_and_gitignore,
)


def test_dockerfile_latest_tag_and_missing_user(tmp_path):
    df = tmp_path / "Dockerfile"
    df.write_text("""FROM python:latest
WORKDIR /app
COPY . /app
CMD ["python", "app.py"]
""")

    findings = scan_dockerfile(df, "Dockerfile")
    rule_ids = [f["rule_id"] for f in findings]

    assert "OG-CFG-001" in rule_ids  # :latest tag
    assert "OG-CFG-002" in rule_ids  # missing USER instruction


def test_dockerfile_with_safe_user(tmp_path):
    df = tmp_path / "Dockerfile"
    df.write_text("""FROM python:3.13-slim
RUN useradd -m appuser
USER appuser
""")

    findings = scan_dockerfile(df, "Dockerfile")
    rule_ids = [f["rule_id"] for f in findings]
    assert "OG-CFG-001" not in rule_ids
    assert "OG-CFG-002" not in rule_ids


def test_docker_compose_privileged(tmp_path):
    dc = tmp_path / "docker-compose.yml"
    dc.write_text("""version: '3.8'
services:
  web:
    image: nginx
    privileged: true
""")
    findings = scan_docker_compose(dc, "docker-compose.yml")
    assert any(f["rule_id"] == "OG-CFG-005" for f in findings)


def test_committed_live_env_file(tmp_path):
    all_files = [".env", "app.py"]
    findings = scan_environment_and_gitignore(tmp_path, all_files)
    assert any(f["rule_id"] == "OG-CFG-007" for f in findings)  # .env committed
    assert any(f["rule_id"] == "OG-CFG-008" for f in findings)  # missing .gitignore

