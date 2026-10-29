"""Secret Detection Module for OpenGuard.

Identifies potential hardcoded API keys, tokens, passwords, private keys,
and connection strings with false-positive filtering and mandatory value masking.
"""

from __future__ import annotations

import logging
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Pattern, Tuple

logger = logging.getLogger(__name__)

# Excluded files where credentials are conventionally placeholders or test data
SAFE_FILENAMES = {
    ".env.example",
    ".env.sample",
    ".env.template",
    "README.md",
    "CHANGELOG.md",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
}

# Values that indicate obvious non-sensitive placeholders
COMMON_PLACEHOLDERS = {
    "your_key", "your_api_key", "your_secret", "your_token", "your-api-key",
    "your-secret-key", "placeholder", "changeme", "change_me", "example",
    "dummy", "dummy_key", "test_key", "test_secret", "insert_key_here",
    "xxxxxxxx", "123456", "password", "secret", "null", "none", "true", "false",
    "undefined", "localhost", "<api_key>", "<your_key>", "${api_key}",
    "process.env", "os.environ",
}


def mask_secret(secret_str: str) -> str:
    """Mask a sensitive token so only boundary characters are visible.

    Never exposes the raw credential in UI, logs, or exports.
    Example: 'AKIA1234567890EXAMPLE' -> 'AKIA************MPLE'
    """
    clean = secret_str.strip("\"' \t\r\n")
    if len(clean) <= 6:
        return "******"
    if len(clean) <= 12:
        return clean[:2] + ("*" * (len(clean) - 4)) + clean[-2:]
    return clean[:4] + ("*" * 12) + clean[-4:]


# Rule Specifications
SECRET_RULES: List[Dict[str, Any]] = [
    {
        "id": "OG-SEC-001",
        "title": "AWS Access Key ID Detected",
        "severity": "Critical",
        "pattern": re.compile(r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})(?![A-Z0-9])"),
        "explanation": "An AWS Access Key ID pattern was detected hardcoded in a source file.",
        "impact": "Exposed AWS keys can grant attackers full programmatic access to your cloud infrastructure and resources.",
        "remediation": "Revoke the exposed key in the AWS IAM Console immediately and use environment variables or AWS Secrets Manager.",
    },
    {
        "id": "OG-SEC-002",
        "title": "OpenAI API Key Detected",
        "severity": "Critical",
        "pattern": re.compile(r"(?<![a-zA-Z0-9_-])(sk-(?:proj-|live-)?[a-zA-Z0-9_-]{24,})(?![a-zA-Z0-9_-])"),
        "explanation": "An OpenAI API Key pattern was found embedded in project files.",
        "impact": "Attackers can deplete your API credit quota, inspect proprietary prompt interactions, or generate unauthorized traffic.",
        "remediation": "Revoke the key immediately in your OpenAI account dashboard and transition to environment variables.",
    },
    {
        "id": "OG-SEC-003",
        "title": "GitHub Personal Access Token Detected",
        "severity": "Critical",
        "pattern": re.compile(r"(?<![a-zA-Z0-9_])(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{30,})(?![a-zA-Z0-9_])"),
        "explanation": "A GitHub personal access token (classic or fine-grained) was detected.",
        "impact": "Provides unauthorized access to private GitHub repositories, workflows, and account settings.",
        "remediation": "Revoke the token in GitHub Developer Settings and configure GitHub Actions secrets or local .env.",
    },
    {
        "id": "OG-SEC-004",
        "title": "Stripe API Key Detected",
        "severity": "Critical",
        "pattern": re.compile(r"(?<![a-zA-Z0-9_])((?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,})(?![a-zA-Z0-9_])"),
        "explanation": "A Stripe secret or restricted API key was detected in source code.",
        "impact": "Exposes payment gateway operations, customer financial records, and unauthorized transaction capabilities.",
        "remediation": "Roll the secret key in Stripe Dashboard and restrict permissions to dedicated backend endpoints.",
    },
    {
        "id": "OG-SEC-005",
        "title": "Slack Token Detected",
        "severity": "High",
        "pattern": re.compile(r"(?<![a-zA-Z0-9_])(xox[baprs]-[0-9a-zA-Z]{10,48})(?![a-zA-Z0-9_])"),
        "explanation": "A Slack bot or user authorization token was detected.",
        "impact": "Allows attackers to impersonate Slack bots, access private channel messages, or extract company discussions.",
        "remediation": "Revoke the token in Slack App Management and retrieve tokens dynamically from secret vaults.",
    },
    {
        "id": "OG-SEC-006",
        "title": "Private Cryptographic Key Detected",
        "severity": "Critical",
        "pattern": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        "explanation": "A private cryptographic key header was detected in project files.",
        "impact": "Compromised private keys allow attackers to decrypt confidential traffic, forge identities, or access remote SSH servers.",
        "remediation": "Remove the private key from version control, generate a fresh keypair, and store private keys outside repository files.",
    },
    {
        "id": "OG-SEC-007",
        "title": "Database Connection String with Credentials Detected",
        "severity": "High",
        "pattern": re.compile(r"((?:postgres|postgresql|mysql|mongodb|mongodb\+srv|redis):\/\/[a-zA-Z0-9_.-]+:([^@\s\"'\<\>]{3,})@[a-zA-Z0-9_.-]+)"),
        "explanation": "A database connection URI containing an embedded plaintext password was detected.",
        "impact": "Exposes database credentials directly, potentially permitting unauthorized data extraction or modification.",
        "remediation": "Externalize database credentials into environment variables (e.g. DATABASE_URL) managed by your hosting platform.",
    },
    {
        "id": "OG-SEC-008",
        "title": "Generic Sensitive Variable Assignment Detected",
        "severity": "Medium",
        "pattern": re.compile(
            r"""(?:api_key|apikey|secret_key|client_secret|db_password|auth_token)\s*[:=]\s*["']([^"'\s]{8,})["']""",
            re.IGNORECASE,
        ),
        "explanation": "A variable name indicating a secret appears to be assigned a hardcoded string value.",
        "impact": "Hardcoded credentials in code may be leaked during deployment or committed to shared repositories.",
        "remediation": "Replace hardcoded credential assignments with dynamic environment variable lookups (e.g., os.getenv).",
    },
]


def is_placeholder(value: str) -> bool:
    """Return True if the matched credential is an obvious sample placeholder."""
    val_clean = value.strip("\"' ").lower()
    if val_clean in COMMON_PLACEHOLDERS:
        return True
    # Explicit prefix/suffix placeholder markers
    for ph in ["your_key", "your-key", "your_api_key", "your-api-key", "placeholder", "changeme", "change_me", "insert_key_here"]:
        if ph in val_clean:
            return True
    return False


def scan_file_for_secrets(file_path: Path, rel_path: str) -> List[Dict[str, Any]]:
    """Scan a single text file for credential patterns with line attribution."""
    findings: List[Dict[str, Any]] = []

    # Skip files known to contain only template/placeholder keys
    p = Path(rel_path)
    if p.name in SAFE_FILENAMES or "test" in str(p).lower():
        # Only check private keys in test files, skip others
        rules_to_run = [r for r in SECRET_RULES if r["id"] == "OG-SEC-006"]
    else:
        rules_to_run = SECRET_RULES

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_no, line in enumerate(f, start=1):
                # Avoid analyzing extremely long lines (minified JS, data URIs)
                if len(line) > 1000:
                    continue

                for rule in rules_to_run:
                    match = rule["pattern"].search(line)
                    if match:
                        matched_str = match.group(0)

                        # Check for placeholder exclusion
                        if is_placeholder(matched_str):
                            continue

                        masked_val = mask_secret(matched_str)
                        masked_line = line.replace(matched_str, masked_val).strip()
                        if len(masked_line) > 120:
                            masked_line = masked_line[:117] + "..."

                        findings.append({
                            "rule_id": rule["id"],
                            "category": "Secrets",
                            "severity": rule["severity"],
                            "title": rule["title"],
                            "file_path": rel_path,
                            "line_number": line_no,
                            "explanation": rule["explanation"],
                            "impact": rule["impact"],
                            "remediation": rule["remediation"],
                            "snippet": masked_line,
                            "masked_value": masked_val,
                        })
                        # Avoid multiple redundant findings on the same line
                        break

    except Exception as e:
        logger.debug("Error scanning file %s for secrets: %s", rel_path, e)

    return findings


def scan_project_secrets(root_dir: Path, inspected_paths: List[str]) -> List[Dict[str, Any]]:
    """Scan all inspected project text files for credentials."""
    all_findings: List[Dict[str, Any]] = []
    root = Path(root_dir).resolve()

    for rel_path in inspected_paths:
        full_path = root / rel_path
        if full_path.exists() and full_path.is_file():
            file_findings = scan_file_for_secrets(full_path, rel_path)
            all_findings.extend(file_findings)

    return all_findings
