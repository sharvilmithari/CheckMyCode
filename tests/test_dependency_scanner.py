"""Unit tests for dependency manifest parsing and CVE advisory detection."""

from pathlib import Path
import pytest

from modules.dependency_scanner import (
    parse_package_json,
    parse_requirements_txt,
    scan_manifest_for_vulnerabilities,
)


def test_parse_requirements_txt():
    content = """
# Comments
requests==2.25.0
flask>=2.0.0
gunicorn
"""
    pkgs = parse_requirements_txt(content)
    assert len(pkgs) == 3
    assert pkgs[0]["package"] == "requests"
    assert pkgs[0]["version"] == "2.25.0"
    assert pkgs[0]["is_pinned"] is True
    assert pkgs[2]["package"] == "gunicorn"
    assert pkgs[2]["is_pinned"] is False


def test_detect_vulnerable_requests_version(tmp_path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requests==2.25.0\n")  # CVE-2023-32681 vulnerable

    findings, stats = scan_manifest_for_vulnerabilities(req_file, "requirements.txt")
    assert stats["packages_found"] == 1
    assert stats["vulnerable_found"] == 1
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "OG-DEP-001"
    assert "CVE-2023-32681" in findings[0]["title"]


def test_detect_unpinned_dependency(tmp_path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("celery\n")

    findings, stats = scan_manifest_for_vulnerabilities(req_file, "requirements.txt")
    assert stats["unpinned_found"] == 1
    assert any(f["rule_id"] == "OG-DEP-002" for f in findings)


def test_parse_package_json_vulnerable_lodash(tmp_path):
    pkg_file = tmp_path / "package.json"
    pkg_file.write_text("""{
  "dependencies": {
    "lodash": "4.17.15"
  }
}""")

    findings, stats = scan_manifest_for_vulnerabilities(pkg_file, "package.json")
    assert stats["packages_found"] == 1
    assert stats["vulnerable_found"] == 1
    assert any("CVE-2021-23337" in f["title"] for f in findings)

