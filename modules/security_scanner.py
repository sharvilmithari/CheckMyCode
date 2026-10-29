"""Static Code Security Scanner for OpenGuard.

Inspects supported Python, JavaScript, and TypeScript source files for
dangerous coding patterns, injection vectors, and insecure configurations.
"""

from __future__ import annotations

import ast
import logging
from pathlib import Path
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

CODE_RULES: List[Dict[str, Any]] = [
    {
        "id": "OG-CODE-001",
        "title": "Unsafe Dynamic Code Execution (eval / exec)",
        "severity": "Critical",
        "languages": ["Python", "JavaScript", "TypeScript"],
        "regex": re.compile(r"\b(?:eval|exec)\s*\((?!['\"][a-zA-Z0-9_\s]+['\"]\))"),
        "explanation": "Dynamic execution functions (eval/exec) can execute arbitrary code if supplied with unverified user input.",
        "impact": "Can allow remote code execution (RCE) and full server takeover.",
        "remediation": "Refactor to use safe alternatives such as ast.literal_eval for Python data or standard JSON parsing.",
    },
    {
        "id": "OG-CODE-002",
        "title": "Subprocess Shell Injection Risk (shell=True)",
        "severity": "High",
        "languages": ["Python"],
        "regex": re.compile(r"subprocess\.(?:Popen|run|call|check_output|check_call)\s*\([^)]*shell\s*=\s*True"),
        "explanation": "Executing subprocess commands with shell=True invokes an intermediate system shell that interprets shell metacharacters.",
        "impact": "Permits arbitrary command injection if command strings incorporate unvalidated user arguments.",
        "remediation": "Pass arguments as a list with shell=False (default): subprocess.run(['cmd', arg1, arg2]).",
    },
    {
        "id": "OG-CODE-003",
        "title": "Potential SQL Injection via Dynamic String Formatting",
        "severity": "High",
        "languages": ["Python", "JavaScript", "TypeScript"],
        "regex": re.compile(
            r"""\b(?:execute|raw_query|cursor\.execute)\s*\(\s*(?:f["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)|["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)[^"']*["']\s*%)""",
            re.IGNORECASE,
        ),
        "explanation": "Constructing SQL statements with string interpolation or formatting bypasses database query parameterization.",
        "impact": "Attackers can manipulate database queries to extract, modify, or delete sensitive records.",
        "remediation": "Always use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,)).",
    },
    {
        "id": "OG-CODE-004",
        "title": "TLS/SSL Certificate Verification Disabled",
        "severity": "High",
        "languages": ["Python", "JavaScript", "TypeScript"],
        "regex": re.compile(r"""(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false)"""),
        "explanation": "Disabling TLS certificate verification (verify=False) accepts any SSL certificate presented by endpoints.",
        "impact": "Exposes HTTP traffic to Man-in-the-Middle (MITM) attacks, enabling interception and tampering of sensitive payloads.",
        "remediation": "Enable standard certificate validation by setting verify=True or providing trusted root CA certificates.",
    },
    {
        "id": "OG-CODE-005",
        "title": "Application Debug Mode Active",
        "severity": "Medium",
        "languages": ["Python", "JavaScript"],
        "regex": re.compile(r"""(?:\bdebug\s*=\s*True\b|\bDEBUG\s*=\s*True\b)"""),
        "explanation": "Framework debug mode is explicitly set to True in code.",
        "impact": "Debug modes in production often expose interactive debug consoles (e.g. Werkzeug pin) or detailed stack traces with secrets.",
        "remediation": "Drive debug settings through environment variables (e.g. os.getenv('APP_DEBUG', 'False').lower() == 'true') and ensure it is False in production.",
    },
    {
        "id": "OG-CODE-006",
        "title": "Insecure Object Deserialization (pickle / unsafe yaml)",
        "severity": "Critical",
        "languages": ["Python"],
        "regex": re.compile(r"""(?:\bpickle\.loads?\s*\(|\byaml\.load\s*\([^)]*Loader\s*=\s*(?:yaml\.)?Loader\b)"""),
        "explanation": "Deserializing untrusted pickle or unconstrained YAML payloads can trigger execution of arbitrary Python objects.",
        "impact": "Enables remote code execution during payload deserialization.",
        "remediation": "Use safe data serialization formats like JSON, or yaml.safe_load() instead of pickle.",
    },
    {
        "id": "OG-CODE-007",
        "title": "Silent Exception Swallowing (except: pass)",
        "severity": "Low",
        "languages": ["Python"],
        "regex": re.compile(r"""except(?:\s+Exception)?\s*:\s*\n?\s*pass\b"""),
        "explanation": "A broad exception block catches and silently suppresses all errors without logging.",
        "impact": "Hides critical database errors, authentication bugs, or permission failures during runtime.",
        "remediation": "Catch specific expected exceptions and log the error context using logging.error().",
    },
    {
        "id": "OG-CODE-008",
        "title": "Insecure Temporary File Creation (tempfile.mktemp)",
        "severity": "Medium",
        "languages": ["Python"],
        "regex": re.compile(r"""\btempfile\.mktemp\s*\("""),
        "explanation": "mktemp is deprecated because it creates an unsafe race condition (TOCTOU) between name generation and file creation.",
        "impact": "Symlink race attacks where malicious processes hijack the generated filename.",
        "remediation": "Use tempfile.NamedTemporaryFile() or tempfile.TemporaryDirectory() which create files securely.",
    },
    {
        "id": "OG-CODE-009",
        "title": "Path Traversal Risk: Unsanitized User Input in File Path",
        "severity": "High",
        "languages": ["Python"],
        "regex": re.compile(r"""(?:open|Path)\s*\(\s*(?:request\.|user_|input|args|params|form\[|query)"""),
        "explanation": "User-controlled input is passed directly to file-opening functions without path validation or sanitization.",
        "impact": "Attackers can traverse directory structures (../) to read or overwrite sensitive files on the server.",
        "remediation": "Use os.path.realpath() or pathlib.Path.resolve() and verify the resolved path starts within an expected base directory.",
    },
    {
        "id": "OG-CODE-010",
        "title": "Server Binding to All Network Interfaces (0.0.0.0)",
        "severity": "Medium",
        "languages": ["Python"],
        "regex": re.compile(r"""(?:host\s*=\s*['"]0\.0\.0\.0['"]|\.run\s*\([^)]*host\s*=\s*['"]0\.0\.0\.0['"])"""),
        "explanation": "The application server is configured to listen on all network interfaces (0.0.0.0) instead of localhost.",
        "impact": "Exposes the application to external network traffic, which is dangerous if the server lacks a reverse proxy or firewall.",
        "remediation": "Bind to 127.0.0.1 (localhost) for development and use a reverse proxy (nginx, Caddy) for production traffic routing.",
    },
    {
        "id": "OG-CODE-011",
        "title": "Wildcard CORS Configuration (Access-Control-Allow-Origin: *)",
        "severity": "Medium",
        "languages": ["Python", "JavaScript", "TypeScript"],
        "regex": re.compile(r"""(?:allow_origins\s*=\s*\[?\s*['\"]\*['\"]|Access-Control-Allow-Origin['":\s]+\*|cors\(\s*\*\s*\)|CORS\s*\(\s*[^)]*origins?\s*=\s*\[?\s*['\"]\*['\"])"""),
        "explanation": "CORS is configured to allow requests from any origin using a wildcard (*), which bypasses same-origin browser protections.",
        "impact": "Allows any third-party website to make authenticated API requests to your backend if cookies or tokens are also misconfigured.",
        "remediation": "Restrict allowed origins to specific trusted domains: allow_origins=['https://yourdomain.com'].",
    },
    {
        "id": "OG-CODE-012",
        "title": "os.system() Command Execution",
        "severity": "High",
        "languages": ["Python"],
        "regex": re.compile(r"""\bos\.system\s*\("""),
        "explanation": "os.system() invokes a system shell to execute a command string, making it vulnerable to shell injection.",
        "impact": "Attackers can inject shell metacharacters to execute arbitrary commands on the host system.",
        "remediation": "Use subprocess.run() with a list of arguments and shell=False (default) instead of os.system().",
    },
]


def scan_file_for_code_security(file_path: Path, rel_path: str) -> List[Dict[str, Any]]:
    """Scan a source file using targeted regex and syntax pattern matching."""
    findings: List[Dict[str, Any]] = []
    p = Path(rel_path)
    ext = p.suffix.lower()

    is_python = ext in [".py", ".pyw"]
    is_js_ts = ext in [".js", ".jsx", ".ts", ".tsx", ".mjs"]

    if not (is_python or is_js_ts):
        return findings

    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        lines = content.splitlines()

        for line_no, line in enumerate(lines, start=1):
            for rule in CODE_RULES:
                # Check language eligibility
                if is_python and "Python" not in rule["languages"]:
                    continue
                if is_js_ts and "JavaScript" not in rule["languages"]:
                    continue

                if rule["regex"].search(line):
                    clean_line = line.strip()
                    if len(clean_line) > 120:
                        clean_line = clean_line[:117] + "..."

                    findings.append({
                        "rule_id": rule["id"],
                        "category": "Code Security",
                        "severity": rule["severity"],
                        "title": rule["title"],
                        "file_path": rel_path,
                        "line_number": line_no,
                        "explanation": rule["explanation"],
                        "impact": rule["impact"],
                        "remediation": rule["remediation"],
                        "snippet": clean_line,
                    })

    except Exception as e:
        logger.debug("Error in code security scanner for %s: %s", rel_path, e)

    return findings


def scan_project_security(root_dir: Path, inspected_paths: List[str]) -> List[Dict[str, Any]]:
    """Scan all source code files for static security anti-patterns."""
    all_findings: List[Dict[str, Any]] = []
    root = Path(root_dir).resolve()

    for rel_path in inspected_paths:
        full_path = root / rel_path
        if full_path.exists() and full_path.is_file():
            file_findings = scan_file_for_code_security(full_path, rel_path)
            all_findings.extend(file_findings)

    return all_findings

