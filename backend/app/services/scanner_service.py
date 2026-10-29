"""Scanning orchestration service for CheckMyCode.

Reuses the proven, working static security scanners from the core modules.
"""

from __future__ import annotations

import logging
from pathlib import Path
import tempfile
from typing import Any, Dict, List, Optional
import uuid

import sys
# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from modules.archive_handler import cleanup_directory, extract_archive_safely
from modules.configuration_scanner import scan_project_configuration
from modules.dependency_scanner import scan_project_dependencies
from modules.project_profiler import profile_project
from modules.risk_scorer import calculate_risk_score
from modules.secret_scanner import scan_project_secrets
from modules.security_scanner import scan_project_security
from modules.report_generator import (
    export_html_report,
    export_json_report,
    export_pdf_report,
    generate_audit_report_dict,
)

logger = logging.getLogger(__name__)

# In-memory scan store (scan_id -> full scan result dict)
_SCAN_STORE: Dict[str, Dict[str, Any]] = {}


def execute_scan(
    archive_bytes_or_path: Any,
    project_name: str,
    prefs: Optional[Dict[str, bool]] = None,
) -> Dict[str, Any]:
    """Execute complete security scan pipeline on a validated project archive."""
    if prefs is None:
        prefs = {"secrets": True, "code_sec": True, "deps": True, "config": True}

    temp_dir = Path(tempfile.mkdtemp(prefix="cmc_fastapi_"))

    try:
        success, err_msg, meta = extract_archive_safely(archive_bytes_or_path, temp_dir)
        if not success:
            raise ValueError(f"Archive validation failed: {err_msg}")

        profile = profile_project(temp_dir)
        profile["project_name"] = project_name

        all_findings: List[Dict[str, Any]] = []
        statuses: Dict[str, str] = {}

        # 1. Secret detection
        if prefs.get("secrets", True):
            sf = scan_project_secrets(temp_dir, profile["inspected_file_paths"])
            all_findings.extend(sf)
            statuses["Secret Detection"] = f"{len(sf)} finding(s)"
        else:
            statuses["Secret Detection"] = "Skipped"

        # 2. Code security
        if prefs.get("code_sec", True):
            cf = scan_project_security(temp_dir, profile["inspected_file_paths"])
            all_findings.extend(cf)
            statuses["Code Security Analysis"] = f"{len(cf)} finding(s)"
        else:
            statuses["Code Security Analysis"] = "Skipped"

        # 3. Dependency CVEs
        if prefs.get("deps", True):
            df, ds = scan_project_dependencies(temp_dir, profile["manifests"])
            all_findings.extend(df)
            pkgs = ds.get("total_packages_checked", 0)
            statuses["Dependency Advisory Scanner"] = f"{pkgs} package(s) checked, {len(df)} finding(s)"
        else:
            statuses["Dependency Advisory Scanner"] = "Skipped"

        # 4. Deployment configuration
        if prefs.get("config", True):
            gf = scan_project_configuration(
                temp_dir, profile["inspected_file_paths"] + profile["configs"]
            )
            all_findings.extend(gf)
            statuses["Deployment Configuration Scanner"] = f"{len(gf)} finding(s)"
        else:
            statuses["Deployment Configuration Scanner"] = "Skipped"

        score_data = calculate_risk_score(all_findings, profile["inspected_files"])

        # Normalize findings with unique IDs if missing
        normalized_findings = []
        for i, f in enumerate(all_findings):
            item = dict(f)
            if "id" not in item:
                item["id"] = f"{item.get('rule_id', 'RULE')}-{i+1}"
            normalized_findings.append(item)

        scan_id = str(uuid.uuid4())
        scan_record = {
            "scan_id": scan_id,
            "project_name": project_name,
            "profile": profile,
            "score_data": score_data,
            "findings": normalized_findings,
            "check_statuses": statuses,
        }

        # Save in memory store for report exports and queries
        _SCAN_STORE[scan_id] = scan_record
        return scan_record

    finally:
        cleanup_directory(temp_dir)


def get_scan(scan_id: str) -> Optional[Dict[str, Any]]:
    return _SCAN_STORE.get(scan_id)


def generate_reports_for_scan(scan_id: str) -> Optional[Dict[str, Any]]:
    scan_record = get_scan(scan_id)
    if not scan_record:
        return None

    report_dict = generate_audit_report_dict(
        scan_record["profile"],
        scan_record["findings"],
        scan_record["score_data"],
        scan_record["check_statuses"],
    )
    return {
        "pdf": export_pdf_report(report_dict),
        "html": export_html_report(report_dict),
        "json": export_json_report(report_dict),
    }

