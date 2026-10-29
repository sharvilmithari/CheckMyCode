"""Unit tests for static code security analysis."""

from pathlib import Path
import pytest

from modules.security_scanner import scan_file_for_code_security


def test_detect_eval_and_exec(tmp_path):
    f = tmp_path / "vulnerable.py"
    f.write_text("""
def run_user_input(code):
    return eval(code)
""")
    findings = scan_file_for_code_security(f, "vulnerable.py")
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "OG-CODE-001"
    assert findings[0]["severity"] == "Critical"
    assert findings[0]["line_number"] == 3


def test_detect_subprocess_shell_true(tmp_path):
    f = tmp_path / "cmd.py"
    f.write_text("""import subprocess
subprocess.run("echo test", shell=True)
""")
    findings = scan_file_for_code_security(f, "cmd.py")
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "OG-CODE-002"
    assert findings[0]["severity"] == "High"


def test_detect_insecure_tls_verify_false(tmp_path):
    f = tmp_path / "fetch.py"
    f.write_text("""import requests
requests.get("https://internal.api", verify=False)
""")
    findings = scan_file_for_code_security(f, "fetch.py")
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "OG-CODE-004"


def test_detect_debug_true(tmp_path):
    f = tmp_path / "app.py"
    f.write_text("""
app.run(debug=True, port=5000)
""")
    findings = scan_file_for_code_security(f, "app.py")
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "OG-CODE-005"

