"""Unit tests for JSON and HTML report generation and credential safety."""

import json
import pytest

from modules.report_generator import (
    export_html_report,
    export_json_report,
    export_pdf_report,
    generate_audit_report_dict,
)


def test_generate_and_export_json_report():
    proj = {
        "project_name": "TestService",
        "total_files": 12,
        "inspected_files": 10,
        "approx_loc": 500,
        "languages": ["Python"],
        "frameworks": ["FastAPI"],
    }
    findings = [
        {
            "rule_id": "OG-SEC-001",
            "category": "Secrets",
            "severity": "Critical",
            "title": "AWS Key Detected",
            "file_path": "backend/auth.py",
            "line_number": 15,
            "explanation": "AWS Key found",
            "remediation": "Revoke key",
            "snippet": "key = 'AKIA************ABCD'",
        }
    ]
    score_data = {
        "score": 75.0,
        "status": "High Risk",
        "critical_count": 1,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "methodology": "Standard deductions",
    }
    check_statuses = {"Secrets": "Completed", "Security": "Completed"}

    report = generate_audit_report_dict(proj, findings, score_data, check_statuses)
    json_str = export_json_report(report)

    parsed = json.loads(json_str)
    assert parsed["metadata"]["platform"] in ["CheckMyCode", "OpenGuard"]
    assert parsed["project_summary"]["project_name"] == "TestService"
    assert parsed["readiness_evaluation"]["score"] == 75.0
    assert len(parsed["findings"]) == 1


def test_export_html_report_escaping():
    proj = {"project_name": "<script>alert('xss')</script>"}
    findings = [
        {
            "rule_id": "OG-CODE-001",
            "severity": "Critical",
            "title": "Malicious <b>title</b>",
            "file_path": "app<script>.py",
            "line_number": 1,
            "explanation": "Test & explanation",
            "remediation": "Test remediation",
            "snippet": "code <tag>",
        }
    ]
    score_data = {"score": 75.0, "status": "Needs Review"}

    report = generate_audit_report_dict(proj, findings, score_data, {})
    html_output = export_html_report(report)

    # Verify HTML escaping
    assert "<script>" not in html_output
    assert "&lt;script&gt;" in html_output
    assert "OpenGuard" in html_output or "CheckMyCode" in html_output


def test_export_pdf_report_valid_binary():
    proj = {
        "project_name": "SecureApp",
        "total_files": 25,
        "inspected_files": 20,
        "approx_loc": 2500,
        "languages": ["Python", "JavaScript"],
        "frameworks": ["FastAPI", "React"],
        "manifests": ["requirements.txt", "package.json"],
    }
    findings = [
        {
            "rule_id": "OG-SEC-001",
            "category": "Secrets",
            "severity": "Critical",
            "title": "AWS Key Detected",
            "file_path": "backend/auth.py",
            "line_number": 15,
            "explanation": "Hardcoded AWS secret key pattern detected in auth file.",
            "impact": "Full programmatic access to cloud resources.",
            "remediation": "Revoke key immediately and use secret vault.",
            "snippet": "AWS_KEY = 'AKIA************ABCD'",
        },
        {
            "rule_id": "OG-CODE-002",
            "category": "Code Security",
            "severity": "High",
            "title": "Subprocess Shell Injection",
            "file_path": "backend/tasks.py",
            "line_number": 42,
            "explanation": "shell=True invokes intermediate shell.",
            "impact": "Arbitrary command execution.",
            "remediation": "Pass arguments as list with shell=False.",
            "snippet": "subprocess.run(cmd, shell=True)",
        },
    ]
    score_data = {
        "score": 68.5,
        "status": "High Risk",
        "critical_count": 1,
        "high_count": 1,
        "medium_count": 0,
        "low_count": 0,
        "methodology": "Deductions applied from 100 baseline with logarithmic dampening.",
    }
    checks = {
        "Secret Detection": "1 finding(s)",
        "Code Security Analysis": "1 finding(s)",
        "Dependency Advisory Scanner": "0 finding(s)",
    }

    report = generate_audit_report_dict(proj, findings, score_data, checks)
    pdf_bytes = export_pdf_report(report)

    assert isinstance(pdf_bytes, bytes)
    # Valid PDF magic bytes header
    assert pdf_bytes.startswith(b"%PDF-")
    # Non-trivial document size
    assert len(pdf_bytes) > 5000
    # Must end with PDF EOF marker or trailer
    assert b"%%EOF" in pdf_bytes


def test_export_pdf_report_zero_findings_graceful():
    proj = {
        "project_name": "CleanProject",
        "total_files": 10,
        "inspected_files": 10,
        "approx_loc": 800,
        "languages": ["Python"],
        "frameworks": [],
        "manifests": [],
    }
    score_data = {
        "score": 100.0,
        "status": "Ship-Ready",
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "methodology": "No deductions.",
    }

    report = generate_audit_report_dict(proj, [], score_data, {})
    pdf_bytes = export_pdf_report(report)

    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF-")
    assert len(pdf_bytes) > 2000
    assert b"%%EOF" in pdf_bytes


