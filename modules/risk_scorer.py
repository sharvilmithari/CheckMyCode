
from __future__ import annotations

import logging
import math
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

# Severity Deduction Weights (per finding)
DEDUCTIONS = {
    "Critical": 25.0,
    "High": 12.0,
    "Medium": 5.0,
    "Low": 2.0,
}


def calculate_risk_score(findings: List[Dict[str, Any]], files_inspected: int) -> Dict[str, Any]:
    """Calculate transparent readiness score based on security findings.

    Scoring methodology:
    - Start at 100 points.
    - Compute raw deductions: Critical * 25 + High * 12 + Medium * 5 + Low * 2.
    - Apply logarithmic dampening: effective_deduction = 30 * ln(1 + raw / 30).
      This compresses large deduction totals so scores remain in a meaningful range.
    - Final score = max(0, min(100, 100 - effective_deduction)), rounded to 1 decimal.
    - Any Critical finding caps the maximum score at 40 ("Critical Block" threshold).
    """
    if files_inspected == 0:
        return {
            "score": 0.0,
            "status": "Unavailable",
            "badge_color": "#8B949E",
            "badge_bg": "#21262D",
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "total_findings": 0,
            "deductions": 0.0,
            "methodology": "No source files were inspected to calculate a readiness score.",
        }

    counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
    }

    for f in findings:
        sev = f.get("severity", "Low")
        if sev in counts:
            counts[sev] += 1
        else:
            counts["Low"] += 1

    raw_deductions = (
        counts["Critical"] * DEDUCTIONS["Critical"]
        + counts["High"] * DEDUCTIONS["High"]
        + counts["Medium"] * DEDUCTIONS["Medium"]
        + counts["Low"] * DEDUCTIONS["Low"]
    )

    # Logarithmic dampening: prevents score from always hitting 0
    # Scale factor of 30 means: first ~30 pts of deductions map roughly 1:1,
    # but 200+ pts of raw deductions compress to ~60-70 effective points,
    # keeping the score informative rather than always zero.
    dampening_factor = 30.0
    effective_deductions = dampening_factor * math.log(1 + raw_deductions / dampening_factor)

    raw_score = 100.0 - effective_deductions

    # If any Critical findings exist, cap score at Critical Block threshold
    if counts["Critical"] > 0:
        raw_score = min(raw_score, 39.9)

    score = round(max(0.0, min(100.0, raw_score)), 1)

    # Readiness Classification
    if score >= 90.0 and counts["Critical"] == 0 and counts["High"] == 0:
        status = "Ship-Ready"
        badge_color = "#10B981"  # Emerald
        badge_bg = "#064E3B"
    elif score >= 70.0 and counts["Critical"] == 0:
        status = "Needs Review"
        badge_color = "#38BDF8"  # Sky
        badge_bg = "#0C4A6E"
    elif score >= 40.0:
        status = "High Risk"
        badge_color = "#F59E0B"  # Amber
        badge_bg = "#78350F"
    else:
        status = "Critical Block"
        badge_color = "#EF4444"  # Red
        badge_bg = "#7F1D1D"

    return {
        "score": score,
        "status": status,
        "badge_color": badge_color,
        "badge_bg": badge_bg,
        "critical_count": counts["Critical"],
        "high_count": counts["High"],
        "medium_count": counts["Medium"],
        "low_count": counts["Low"],
        "total_findings": len(findings),
        "deductions": round(effective_deductions, 1),
        "raw_deductions": round(raw_deductions, 1),
        "methodology": (
            "Score starts at 100. Raw deductions: Critical (-25 pts), High (-12 pts), "
            "Medium (-5 pts), Low (-2 pts). Logarithmic dampening applied: "
            "effective = 30 * ln(1 + raw/30). Critical findings cap max score at 40."
        ),
    }

