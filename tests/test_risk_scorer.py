"""Unit tests for deterministic readiness risk scoring."""

import pytest

from modules.risk_scorer import calculate_risk_score


def test_perfect_score_zero_findings():
    res = calculate_risk_score([], files_inspected=10)
    assert res["score"] == 100.0
    assert res["status"] == "Ship-Ready"
    assert res["critical_count"] == 0


def test_deductions_critical_finding():
    findings = [
        {"severity": "Critical", "rule_id": "OG-SEC-001"},
    ]
    res = calculate_risk_score(findings, files_inspected=5)
    # With logarithmic dampening and Critical cap at 39.9, score should be capped
    assert res["score"] <= 39.9  # Critical findings cap score at Critical Block
    assert res["critical_count"] == 1
    assert res["status"] == "Critical Block"


def test_empty_files_inspected():
    res = calculate_risk_score([], files_inspected=0)
    assert res["score"] == 0.0
    assert res["status"] == "Unavailable"


def test_score_never_exceeds_bounds():
    # Severe findings overwhelming the score
    findings = [{"severity": "Critical"}] * 10
    res = calculate_risk_score(findings, files_inspected=5)
    assert 0.0 <= res["score"] <= 100.0
    assert res["status"] == "Critical Block"


def test_logarithmic_dampening_keeps_score_informative():
    """Many high-severity findings should not always bottom out at 0."""
    # 5 High + 5 Medium findings: raw deductions = 5*12 + 5*5 = 85
    # Without dampening: score = 15. With dampening: score > 15.
    findings = [{"severity": "High"}] * 5 + [{"severity": "Medium"}] * 5
    res = calculate_risk_score(findings, files_inspected=20)
    # Score should be positive and greater than naive 100-85=15 due to dampening
    assert res["score"] > 15.0
    assert res["score"] < 100.0
    # No critical findings, so no Critical Block cap
    assert res["critical_count"] == 0


def test_score_with_only_low_findings():
    findings = [{"severity": "Low"}] * 3
    res = calculate_risk_score(findings, files_inspected=10)
    # 3 * 2 = 6 raw deductions, dampened ~5.4
    assert res["score"] > 90.0
    assert res["status"] == "Ship-Ready"
