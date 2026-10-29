"""Dependency Vulnerability Analysis Module for OpenGuard.

Parses dependency manifests (requirements.txt, package.json, pyproject.toml)
and evaluates installed versions against a curated advisory database of known
vulnerabilities and unpinned supply-chain risks.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Curated Offline Advisory Database for Notable High/Critical Package CVEs
KNOWN_ADVISORIES: List[Dict[str, Any]] = [
    {
        "ecosystem": "PyPI",
        "package": "requests",
        "vulnerable_before": "2.31.0",
        "cve": "CVE-2023-32681",
        "severity": "High",
        "summary": "Requests Proxy-Authorization Header Leak to HTTPS Proxies during Redirects",
        "fix_version": "2.31.0",
    },
    {
        "ecosystem": "PyPI",
        "package": "urllib3",
        "vulnerable_before": "1.26.18",
        "cve": "CVE-2023-45803",
        "severity": "High",
        "summary": "HTTP Request Body and Authorization Header Leakage on 303 Redirects",
        "fix_version": "1.26.18 or 2.0.7",
    },
    {
        "ecosystem": "PyPI",
        "package": "flask",
        "vulnerable_before": "2.2.5",
        "cve": "CVE-2023-30861",
        "severity": "High",
        "summary": "Cookie Session Insecurity in Misconfigured Caching Proxies",
        "fix_version": "2.2.5",
    },
    {
        "ecosystem": "PyPI",
        "package": "jinja2",
        "vulnerable_before": "3.1.3",
        "cve": "CVE-2024-22195",
        "severity": "Medium",
        "summary": "Jinja XML/HTML Attribute Injection in xmlattr Filter",
        "fix_version": "3.1.3",
    },
    {
        "ecosystem": "PyPI",
        "package": "django",
        "vulnerable_before": "4.2.10",
        "cve": "CVE-2024-24680",
        "severity": "High",
        "summary": "Denial of Service via High-Cardinality Introspection in Form Rendering",
        "fix_version": "4.2.10 or 5.0.2",
    },
    {
        "ecosystem": "PyPI",
        "package": "cryptography",
        "vulnerable_before": "41.0.6",
        "cve": "CVE-2023-49083",
        "severity": "High",
        "summary": "NULL-pointer Dereference in PKCS7 Certificate Verification",
        "fix_version": "41.0.6",
    },
    {
        "ecosystem": "npm",
        "package": "lodash",
        "vulnerable_before": "4.17.21",
        "cve": "CVE-2021-23337",
        "severity": "High",
        "summary": "Prototype Pollution in lodash.template",
        "fix_version": "4.17.21",
    },
    {
        "ecosystem": "npm",
        "package": "axios",
        "vulnerable_before": "1.6.0",
        "cve": "CVE-2023-45857",
        "severity": "High",
        "summary": "Cross-Site Request Forgery (CSRF) and SSRF via Path Relative Redirects",
        "fix_version": "1.6.0",
    },
    {
        "ecosystem": "npm",
        "package": "express",
        "vulnerable_before": "4.19.2",
        "cve": "CVE-2024-29041",
        "severity": "Medium",
        "summary": "Open Redirect via Malformed Request Path Parsing",
        "fix_version": "4.19.2",
    },
]


def parse_semver_tuple(v_str: str) -> Tuple[int, ...]:
    """Parse semver string into comparable integer tuple."""
    nums = re.findall(r"\d+", v_str)
    if not nums:
        return (0, 0, 0)
    return tuple(int(n) for n in nums[:3])


def parse_requirements_txt(content: str) -> List[Dict[str, Any]]:
    """Parse Python requirements.txt entries into package names and pinned versions."""
    packages = []
    lines = content.splitlines()

    for line_no, line in enumerate(lines, start=1):
        cleaned = line.split("#")[0].strip()
        if not cleaned or cleaned.startswith("-"):
            continue

        # Match package==version or package>=version or package
        m = re.match(r"^([a-zA-Z0-9_.-]+)(?:([=><~!^]+)(.*))?$", cleaned)
        if m:
            pkg_name = m.group(1).lower().strip()
            operator = m.group(2) or ""
            version = (m.group(3) or "").strip()
            packages.append({
                "package": pkg_name,
                "operator": operator,
                "version": version,
                "raw": cleaned,
                "is_pinned": operator in ["==", "==="],
                "line_number": line_no,
            })

    return packages


def parse_package_json(content: str) -> List[Dict[str, Any]]:
    """Parse npm package.json dependencies."""
    packages = []
    try:
        data = json.loads(content)
        deps: Dict[str, str] = {}
        deps.update(data.get("dependencies", {}))
        deps.update(data.get("devDependencies", {}))

        # Build a line number lookup by scanning the raw content
        lines = content.splitlines()
        pkg_line_map: Dict[str, int] = {}
        for line_no, line in enumerate(lines, start=1):
            # Match "package-name": "version" patterns in JSON
            m = re.search(r'"([^"]+)"\s*:\s*"([^"]*)"', line)
            if m:
                pkg_line_map[m.group(1).lower().strip()] = line_no

        for pkg, ver in deps.items():
            clean_ver = re.sub(r"[^0-9.]", "", ver)
            packages.append({
                "package": pkg.lower().strip(),
                "operator": "^" if "^" in ver else ("~" if "~" in ver else "="),
                "version": clean_ver,
                "raw": f"{pkg}: {ver}",
                "is_pinned": not (ver == "*" or "latest" in ver),
                "line_number": pkg_line_map.get(pkg.lower().strip()),
            })
    except Exception as e:
        logger.debug("Failed to parse package.json: %s", e)

    return packages


def scan_manifest_for_vulnerabilities(
    manifest_path: Path,
    rel_path: str,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Scan a single dependency manifest for known CVEs and unpinned supply-chain risks."""
    findings: List[Dict[str, Any]] = []
    manifest_name = manifest_path.name
    content = manifest_path.read_text(encoding="utf-8", errors="ignore")

    stats = {
        "manifest": rel_path,
        "packages_found": 0,
        "vulnerable_found": 0,
        "unpinned_found": 0,
    }

    if manifest_name in ["requirements.txt", "Pipfile"] or "requirements" in manifest_name:
        parsed_pkgs = parse_requirements_txt(content)
        ecosystem = "PyPI"
    elif manifest_name == "package.json":
        parsed_pkgs = parse_package_json(content)
        ecosystem = "npm"
    else:
        return findings, stats

    stats["packages_found"] = len(parsed_pkgs)

    for item in parsed_pkgs:
        pkg_name = item["package"]
        ver_str = item["version"]
        pkg_line = item.get("line_number")

        # 1. Supply-chain check: completely unpinned dependency
        if not ver_str or item["operator"] == "" or ver_str == "*":
            stats["unpinned_found"] += 1
            findings.append({
                "rule_id": "OG-DEP-002",
                "category": "Dependency Risks",
                "severity": "Low",
                "title": f"Unpinned Dependency Version: '{pkg_name}'",
                "file_path": rel_path,
                "line_number": pkg_line,
                "explanation": f"Package '{pkg_name}' is specified without an explicit pinned version.",
                "impact": "Builds and deployments can silently pull breaking or compromised upstream package versions.",
                "remediation": f"Pin the dependency to a verified version (e.g. {pkg_name}==X.Y.Z) or generate a lockfile.",
                "snippet": item["raw"],
            })
            continue

        # 2. Check against known vulnerability advisories
        if ver_str:
            item_semver = parse_semver_tuple(ver_str)
            for adv in KNOWN_ADVISORIES:
                if adv["ecosystem"] == ecosystem and adv["package"] == pkg_name:
                    vuln_before = parse_semver_tuple(adv["vulnerable_before"])
                    if item_semver < vuln_before:
                        stats["vulnerable_found"] += 1
                        findings.append({
                            "rule_id": "OG-DEP-001",
                            "category": "Dependency Risks",
                            "severity": adv["severity"],
                            "title": f"Vulnerable Package Version: {pkg_name} ({adv['cve']})",
                            "file_path": rel_path,
                            "line_number": pkg_line,
                            "explanation": f"Package '{pkg_name}' version {ver_str} is vulnerable to {adv['cve']}: {adv['summary']}.",
                            "impact": "Exposes application to known security advisories that can be exploited by automated attacks.",
                            "remediation": f"Upgrade '{pkg_name}' to version {adv['fix_version']} or later.",
                            "snippet": item["raw"],
                        })

    return findings, stats


def scan_project_dependencies(
    root_dir: Path,
    manifests: List[str],
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Scan all project dependency manifests."""
    all_findings: List[Dict[str, Any]] = []
    root = Path(root_dir).resolve()
    summary: Dict[str, Any] = {
        "manifests_analyzed": len(manifests),
        "total_packages_checked": 0,
        "packages_found": 0,
        "advisory_lookup_source": "OpenGuard Curated Advisory DB (Offline Mode)",
    }

    for rel_path in manifests:
        full_path = root / rel_path
        if full_path.exists() and full_path.is_file():
            findings, stats = scan_manifest_for_vulnerabilities(full_path, rel_path)
            all_findings.extend(findings)
            summary["total_packages_checked"] += stats["packages_found"]
            summary["packages_found"] += stats["packages_found"]

    return all_findings, summary

