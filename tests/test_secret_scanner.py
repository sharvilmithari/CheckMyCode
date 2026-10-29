"""Unit tests for secret detection, masking, and false-positive exclusion."""

from pathlib import Path
import pytest

from modules.secret_scanner import mask_secret, scan_file_for_secrets, scan_project_secrets


def test_mask_secret():
    assert mask_secret("short") == "******"
    aws_key = "AKIA1234567890ABCDEF"
    masked = mask_secret(aws_key)
    assert masked.startswith("AKIA")
    assert masked.endswith("CDEF")
    assert "1234567890" not in masked
    assert "*" in masked


def test_detect_aws_and_openai_secrets(tmp_path):
    f = tmp_path / "secrets.py"
    # Use realistic dummy credentials
    f.write_text("""
aws_key = "AKIAIOSFODNN7EXAMPLE"
openai_key = "sk-live-abcdef1234567890abcdef123456"
db_url = "postgres://admin:supersecret99@db.local:5432/db"
""")

    findings = scan_file_for_secrets(f, "secrets.py")
    assert len(findings) >= 2

    rule_ids = [item["rule_id"] for item in findings]
    assert "OG-SEC-001" in rule_ids  # AWS
    assert "OG-SEC-002" in rule_ids  # OpenAI

    # Verify no raw secrets leaked in findings snippets
    for item in findings:
        assert "AKIAIOSFODNN7EXAMPLE" not in item["snippet"]
        assert "sk-live-abcdef1234567890abcdef123456" not in item["snippet"]


def test_false_positive_exclusion_for_example_files(tmp_path):
    # .env.example should NOT flag placeholder credentials
    env_ex = tmp_path / ".env.example"
    env_ex.write_text("""
OPENAI_API_KEY=your_key_here
DATABASE_URL=postgres://user:placeholder_pass@localhost:5432/dev
""")

    findings = scan_file_for_secrets(env_ex, ".env.example")
    assert len(findings) == 0


def test_generic_common_placeholder_ignored(tmp_path):
    f = tmp_path / "config.py"
    f.write_text('API_KEY = "insert_key_here"')
    findings = scan_file_for_secrets(f, "config.py")
    assert len(findings) == 0

