"""Deployment and Configuration Scanner for CheckMyCode.

Inspects Dockerfiles, docker-compose manifests, environment files, and .gitignore
for insecure deployment configurations, root privilege risks, and credential leaks.
"""

from __future__ import annotations

import logging
from pathlib import Path
import re
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


def scan_dockerfile(dockerfile_path: Path, rel_path: str) -> List[Dict[str, Any]]:
    """Scan Dockerfile for container security best practices."""
    findings: List[Dict[str, Any]] = []
    try:
        content = dockerfile_path.read_text(encoding="utf-8", errors="ignore")
        lines = content.splitlines()

        has_user_instruction = False

        for line_no, line in enumerate(lines, start=1):
            clean = line.strip()
            if not clean or clean.startswith("#"):
                continue

            # 1. Base image using latest tag or unpinned
            if re.match(r"^FROM\s+[^\s:]+(?::latest|\s*$)", clean, re.IGNORECASE):
                findings.append({
                    "rule_id": "OG-CFG-001",
                    "category": "Deployment Configuration",
                    "severity": "Medium",
                    "title": "Dockerfile Base Image Uses Untagged or ':latest' Version",
                    "file_path": rel_path,
                    "line_number": line_no,
                    "explanation": "Using unpinned or ':latest' base images causes non-deterministic builds and introduces breaking upstream changes.",
                    "impact": "Unpredictable builds and unintended introduction of untested image layers in production.",
                    "remediation": "Pin base images to an explicit, immutable version digest or specific release tag (e.g., python:3.13-slim).",
                    "snippet": clean,
                })

            # 2. Check for USER instruction
            if re.match(r"^USER\s+", clean, re.IGNORECASE):
                has_user_instruction = True

            # 3. Hardcoded ENV secrets in Dockerfile
            if re.match(r"^ENV\s+.*(?:KEY|SECRET|PASSWORD|TOKEN|PASS)\s*=", clean, re.IGNORECASE):
                findings.append({
                    "rule_id": "OG-CFG-003",
                    "category": "Deployment Configuration",
                    "severity": "High",
                    "title": "Potential Hardcoded Credential in Dockerfile ENV Directive",
                    "file_path": rel_path,
                    "line_number": line_no,
                    "explanation": "ENV instructions bake values directly into container image layers permanently.",
                    "impact": "Anyone with access to the container image can extract credentials using 'docker inspect' or 'docker history'.",
                    "remediation": "Inject secrets at runtime using container orchestration secret stores or Docker BuildKit secrets.",
                    "snippet": clean,
                })

            # 4. Insecure ADD instruction fetching from remote URL or unpacking untrusted files
            if re.match(r"^ADD\s+https?://", clean, re.IGNORECASE):
                findings.append({
                    "rule_id": "OG-CFG-004",
                    "category": "Deployment Configuration",
                    "severity": "Medium",
                    "title": "Insecure Remote Archive or URL in Dockerfile ADD Directive",
                    "file_path": rel_path,
                    "line_number": line_no,
                    "explanation": "Using ADD to fetch remote archives bypasses checksum verification and may introduce malicious payloads.",
                    "impact": "Remote file tampering or Man-in-the-Middle attack risk during container build.",
                    "remediation": "Use RUN curl or wget with explicit hash verification, and prefer COPY for local files.",
                    "snippet": clean,
                })

        # 5. Missing USER directive (Container runs as root)
        if not has_user_instruction:
            findings.append({
                "rule_id": "OG-CFG-002",
                "category": "Deployment Configuration",
                "severity": "Medium",
                "title": "Container Image Runs as Default 'root' User",
                "file_path": rel_path,
                "line_number": 1,
                "explanation": "No 'USER' instruction was detected. By default, processes inside the container will execute with root privileges.",
                "impact": "If an attacker achieves remote code execution within the container, they inherit root capabilities, increasing container breakout risk.",
                "remediation": "Create and switch to a non-root application user: RUN useradd -m appuser && USER appuser.",
                "snippet": "File-level finding: Missing USER instruction in Dockerfile",
            })

    except Exception as e:
        logger.debug("Error scanning Dockerfile %s: %s", rel_path, e)

    return findings


def scan_docker_compose(compose_path: Path, rel_path: str) -> List[Dict[str, Any]]:
    """Scan docker-compose files for insecure container capabilities and port bindings."""
    findings: List[Dict[str, Any]] = []
    try:
        content = compose_path.read_text(encoding="utf-8", errors="ignore")
        lines = content.splitlines()

        for line_no, line in enumerate(lines, start=1):
            clean = line.strip()

            # Privileged mode
            if re.search(r"privileged\s*:\s*true", clean, re.IGNORECASE):
                findings.append({
                    "rule_id": "OG-CFG-005",
                    "category": "Deployment Configuration",
                    "severity": "High",
                    "title": "Privileged Container Mode Enabled in Docker Compose",
                    "file_path": rel_path,
                    "line_number": line_no,
                    "explanation": "Running containers with 'privileged: true' gives the container full access to the host kernel and devices.",
                    "impact": "Completely invalidates container isolation and allows straightforward host-level privilege escalation.",
                    "remediation": "Remove 'privileged: true' and grant only explicit Linux capabilities needed using cap_add.",
                    "snippet": clean,
                })

            # Exposed database ports directly on all interfaces
            if re.search(r"""["']?(?:0\.0\.0\.0:)?(?:5432|3306|27017|6379):\d+["']?""", clean):
                findings.append({
                    "rule_id": "OG-CFG-006",
                    "category": "Deployment Configuration",
                    "severity": "Medium",
                    "title": "Database Port Exposed to All Network Interfaces (0.0.0.0)",
                    "file_path": rel_path,
                    "line_number": line_no,
                    "explanation": "A database port appears mapped directly to external host interfaces rather than isolated within internal container networks.",
                    "impact": "Allows external network actors to directly access database service login prompts if firewall rules fail.",
                    "remediation": "Bind only to localhost (127.0.0.1:5432:5432) or rely solely on private internal Docker networks for app-to-database communication.",
                    "snippet": clean,
                })

    except Exception as e:
        logger.debug("Error scanning compose file %s: %s", rel_path, e)

    return findings


def scan_environment_and_gitignore(root_dir: Path, all_files: List[str]) -> List[Dict[str, Any]]:
    """Inspect presence of .env files and gitignore coverage."""
    findings: List[Dict[str, Any]] = []
    root = Path(root_dir).resolve()

    has_gitignore = False
    gitignore_excludes_env = False
    gitignore_rel_path = ".gitignore"

    for rel_path in all_files:
        p = Path(rel_path)

        # Check for actual live .env included in archive
        if p.name == ".env" or (p.name.startswith(".env.") and p.name not in [".env.example", ".env.sample", ".env.template"]):
            findings.append({
                "rule_id": "OG-CFG-007",
                "category": "Deployment Configuration",
                "severity": "High",
                "title": f"Live Environment File ({p.name}) Committed in Project Archive",
                "file_path": rel_path,
                "line_number": 1,
                "explanation": f"An actual {p.name} file was packaged inside the project archive instead of an example template.",
                "impact": "Live environment files frequently contain database passwords, production secret keys, and API tokens.",
                "remediation": "Add .env to your .gitignore, remove it from git tracking, and provide only .env.example with placeholder keys.",
                "snippet": f"File-level finding: {p.name} packaged in repository archive",
            })

        if p.name == ".gitignore":
            has_gitignore = True
            gitignore_rel_path = rel_path
            try:
                content = (root / rel_path).read_text(encoding="utf-8", errors="ignore")
                for line in content.splitlines():
                    clean_l = line.strip()
                    if clean_l == ".env" or clean_l.startswith("*.env") or ".env*" in clean_l:
                        gitignore_excludes_env = True
                        break
            except Exception:
                pass

    if not has_gitignore:
        findings.append({
            "rule_id": "OG-CFG-008",
            "category": "Deployment Configuration",
            "severity": "Low",
            "title": "Missing '.gitignore' File",
            "file_path": ".gitignore",
            "line_number": None,
            "explanation": "No .gitignore file was detected in the project root.",
            "impact": "High risk of accidental commits of temporary files, local secrets, virtual environments, and node_modules.",
            "remediation": "Create a standard .gitignore suitable for your project language and framework.",
            "snippet": "Project-level finding: Missing .gitignore",
        })
    elif not gitignore_excludes_env:
        findings.append({
            "rule_id": "OG-CFG-009",
            "category": "Deployment Configuration",
            "severity": "Medium",
            "title": "'.gitignore' Does Not Exclude '.env' Files",
            "file_path": gitignore_rel_path,
            "line_number": 1,
            "explanation": "Your .gitignore file does not include an explicit entry for '.env'.",
            "impact": "Developers may accidentally stage and commit local credentials to shared repositories.",
            "remediation": "Add '.env' and '.env.local' to your .gitignore file.",
            "snippet": "Configuration finding: .env missing from .gitignore entries",
        })

    return findings


def scan_project_configuration(root_dir: Path, all_files: List[str]) -> List[Dict[str, Any]]:
    """Scan all configuration and deployment descriptors."""
    findings: List[Dict[str, Any]] = []
    root = Path(root_dir).resolve()

    # Deduplicate file list while preserving order
    unique_files: List[str] = []
    seen = set()
    for f in all_files:
        if f not in seen:
            seen.add(f)
            unique_files.append(f)

    for rel_path in unique_files:
        full_path = root / rel_path
        if not (full_path.exists() and full_path.is_file()):
            continue

        filename = full_path.name.lower()
        if filename == "dockerfile" or filename.startswith("dockerfile."):
            findings.extend(scan_dockerfile(full_path, rel_path))
        elif filename in ["docker-compose.yml", "docker-compose.yaml"]:
            findings.extend(scan_docker_compose(full_path, rel_path))

    # Environment & gitignore scan (run once per unique files list)
    findings.extend(scan_environment_and_gitignore(root_dir, unique_files))

    return findings
