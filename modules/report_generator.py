from __future__ import annotations

from datetime import datetime, timezone
import html
from io import BytesIO
import json
import logging
from pathlib import Path
import textwrap
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def generate_audit_report_dict(
    project_profile: Dict[str, Any],
    findings: List[Dict[str, Any]],
    score_data: Dict[str, Any],
    check_statuses: Dict[str, str],
) -> Dict[str, Any]:
    """Compile comprehensive structured audit report dictionary."""
    return {
        "metadata": {
            "platform": "CheckMyCode",
            "legacy_platform": "OpenGuard",
            "version": "1.1.0",
            "tagline": "Find the risks. Fix them before you ship.",
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        },
        "project_summary": {
            "project_name": project_profile.get("project_name", "Unknown"),
            "total_files": project_profile.get("total_files", 0),
            "inspected_files": project_profile.get("inspected_files", 0),
            "approx_lines_of_code": project_profile.get("approx_loc", 0),
            "languages": project_profile.get("languages", []),
            "frameworks": project_profile.get("frameworks", []),
            "manifests": project_profile.get("manifests", []),
        },
        "readiness_evaluation": {
            "score": score_data.get("score", 0.0),
            "status": score_data.get("status", "Unavailable"),
            "critical_issues": score_data.get("critical_count", 0),
            "high_issues": score_data.get("high_count", 0),
            "medium_issues": score_data.get("medium_count", 0),
            "low_issues": score_data.get("low_count", 0),
            "scoring_methodology": score_data.get("methodology", ""),
        },
        "executed_checks": check_statuses,
        "findings_summary": {
            "total_findings": len(findings),
            "by_category": {
                "Secrets": sum(1 for f in findings if f.get("category") == "Secrets"),
                "Code Security": sum(1 for f in findings if f.get("category") == "Code Security"),
                "Dependency Risks": sum(1 for f in findings if f.get("category") == "Dependency Risks"),
                "Deployment Configuration": sum(1 for f in findings if f.get("category") == "Deployment Configuration"),
            },
        },
        "findings": findings,
        "trust_and_limitations": (
            "CheckMyCode (formerly OpenGuard) identifies potential issues using its implemented static and rule-based checks. "
            "It is not a substitute for a professional manual security audit, comprehensive penetration testing, "
            "or formal verification. Clean results indicate only that no issues matched the implemented rules."
        ),
    }


def export_json_report(report_data: Dict[str, Any], indent: int = 2) -> str:
    """Serialize report dictionary to formatted JSON string."""
    return json.dumps(report_data, indent=indent, ensure_ascii=False)


def export_html_report(report_data: Dict[str, Any]) -> str:
    """Render a standalone, self-contained HTML audit report with embedded styling."""
    meta = report_data.get("metadata", {})
    proj = report_data.get("project_summary", {})
    readiness = report_data.get("readiness_evaluation", {})
    findings = report_data.get("findings", [])

    status_color = (
        "#22D3EE"
        if readiness.get("score", 0) >= 90
        else "#3478F6"
        if readiness.get("score", 0) >= 70
        else "#F5C451"
        if readiness.get("score", 0) >= 40
        else "#FF4D5E"
    )

    findings_rows = []
    for f in findings:
        sev = html.escape(str(f.get("severity", "Low")))
        rule_id = html.escape(str(f.get("rule_id", "")))
        title = html.escape(str(f.get("title", "")))
        file_p = html.escape(str(f.get("file_path", "")))
        line_n = str(f.get("line_number")) if f.get("line_number") is not None else "—"
        expl = html.escape(str(f.get("explanation", "")))
        remed = html.escape(str(f.get("remediation", "")))
        snippet = html.escape(str(f.get("snippet", "")))

        sev_badge = (
            f'<span style="background:rgba(255,77,94,0.18);color:#FF4D5E;border:1px solid rgba(255,77,94,0.4);padding:3px 9px;border-radius:4px;font-size:11px;font-weight:700;">{sev}</span>'
            if sev == "Critical"
            else f'<span style="background:rgba(255,138,61,0.18);color:#FF8A3D;border:1px solid rgba(255,138,61,0.4);padding:3px 9px;border-radius:4px;font-size:11px;font-weight:700;">{sev}</span>'
            if sev == "High"
            else f'<span style="background:rgba(245,196,81,0.18);color:#F5C451;border:1px solid rgba(245,196,81,0.4);padding:3px 9px;border-radius:4px;font-size:11px;font-weight:700;">{sev}</span>'
            if sev == "Medium"
            else f'<span style="background:rgba(79,156,249,0.18);color:#4F9CF9;border:1px solid rgba(79,156,249,0.4);padding:3px 9px;border-radius:4px;font-size:11px;font-weight:700;">{sev}</span>'
        )

        findings_rows.append(f"""
        <tr style="border-bottom: 1px solid #24334B;">
            <td style="padding: 12px 14px; vertical-align: top;">{sev_badge}</td>
            <td style="padding: 12px 14px; vertical-align: top; font-family: 'JetBrains Mono', monospace; font-size: 12px; color: #A7B3C8;">{rule_id}</td>
            <td style="padding: 12px 14px; vertical-align: top;">
                <div style="font-weight: 600; color: #F5F7FB; margin-bottom: 4px; font-size: 14px;">{title}</div>
                <div style="font-size: 12px; color: #A7B3C8; margin-bottom: 6px; line-height: 1.5;">{expl}</div>
                <div style="font-size: 12px; color: #22D3EE; line-height: 1.5;"><strong>Recommended Fix:</strong> {remed}</div>
                {f'<pre style="background:#080B12;border:1px solid #24334B;padding:8px 12px;border-radius:6px;font-size:11px;margin-top:8px;overflow-x:auto;color:#F5F7FB;font-family:\'JetBrains Mono\',monospace;">{snippet}</pre>' if snippet else ''}
            </td>
            <td style="padding: 12px 14px; vertical-align: top; font-family: 'JetBrains Mono', monospace; font-size: 12px; color: #3478F6;">{file_p}:{line_n}</td>
        </tr>
        """)

    table_body = "".join(findings_rows) if findings_rows else "<tr><td colspan='4' style='padding:28px;text-align:center;color:#22D3EE;font-size:14px;'>No security findings detected across implemented checks.</td></tr>"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>CheckMyCode Audit Report — {html.escape(proj.get('project_name', 'Project'))}</title>
    <style>
        body {{
            background-color: #080B12;
            color: #A7B3C8;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            margin: 0;
            padding: 36px 44px;
        }}
        .container {{ max-width: 1100px; margin: 0 auto; }}
        .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #24334B; padding-bottom: 20px; margin-bottom: 28px; }}
        .brand {{ font-size: 24px; font-weight: 800; color: #F5F7FB; letter-spacing: -0.02em; }}
        .brand span {{ color: #3478F6; }}
        .meta-pill {{ background: #111B2D; border: 1px solid #24334B; border-radius: 6px; padding: 6px 14px; font-size: 12px; color: #A7B3C8; font-family: monospace; }}
        .grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 28px; }}
        .card {{ background: #111B2D; border: 1px solid #24334B; border-radius: 10px; padding: 16px 20px; }}
        .card-label {{ font-size: 11px; text-transform: uppercase; color: #718096; letter-spacing: 0.08em; font-weight: 700; }}
        .card-val {{ font-size: 26px; font-weight: 800; color: #F5F7FB; margin: 6px 0; font-family: monospace; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 14px; background: #111B2D; border: 1px solid #24334B; border-radius: 10px; overflow: hidden; }}
        th {{ background: #0D1424; text-align: left; padding: 12px 14px; font-size: 11px; text-transform: uppercase; color: #718096; border-bottom: 1px solid #24334B; letter-spacing: 0.06em; font-weight: 700; }}
        .disclaimer {{ background: #0D1424; border: 1px solid #24334B; border-left: 3px solid #3478F6; border-radius: 8px; padding: 16px 18px; margin-top: 32px; font-size: 12px; color: #718096; line-height: 1.6; }}
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <div>
            <div class="brand">Check<span>MyCode</span></div>
            <div style="font-size: 13px; color: #A7B3C8; margin-top: 4px;">Find the risks. Fix them before you ship.</div>
            <div style="font-size: 11px; color: #718096; margin-top: 2px;">Powered by OpenGuard engine</div>
        </div>
        <div class="meta-pill">Generated: {html.escape(meta.get('generated_at_utc', '')[:19])} UTC</div>
    </div>

    <div class="grid">
        <div class="card">
            <div class="card-label">Project Name</div>
            <div class="card-val" style="font-size: 18px; word-break: break-all;">{html.escape(proj.get('project_name', 'Unknown'))}</div>
            <div style="font-size: 12px; color: #718096;">{proj.get('inspected_files', 0)} files inspected</div>
        </div>
        <div class="card">
            <div class="card-label">Readiness Score</div>
            <div class="card-val" style="color: {status_color};">{readiness.get('score', 0)}/100</div>
            <div style="font-size: 12px; color: {status_color}; font-weight: 600;">{html.escape(readiness.get('status', ''))}</div>
        </div>
        <div class="card">
            <div class="card-label">Total Findings</div>
            <div class="card-val">{len(findings)}</div>
            <div style="font-size: 12px; color: #FF4D5E;">{readiness.get('critical_count', 0)} Critical &bull; {readiness.get('high_count', 0)} High</div>
        </div>
        <div class="card">
            <div class="card-label">Languages Detected</div>
            <div class="card-val" style="font-size: 16px; margin-top: 8px;">{html.escape(', '.join(proj.get('languages', [])) or 'None')}</div>
            <div style="font-size: 12px; color: #718096;">{proj.get('approx_lines_of_code', 0):,} approx LOC</div>
        </div>
    </div>

    <h3 style="color: #F5F7FB; margin-top: 32px; margin-bottom: 8px; font-size: 16px;">Security Audit Findings</h3>
    <table>
        <thead>
            <tr>
                <th style="width: 100px;">Severity</th>
                <th style="width: 120px;">Rule ID</th>
                <th>Finding Details &amp; Remediation</th>
                <th style="width: 220px;">Location</th>
            </tr>
        </thead>
        <tbody>
            {table_body}
        </tbody>
    </table>

    <div class="disclaimer">
        <strong style="color:#A7B3C8;">Trust &amp; Verification Notice:</strong> {html.escape(report_data.get('trust_and_limitations', ''))}
    </div>
</div>
</body>
</html>
"""
    return html_content


def _wrap_snippet(code: str, max_line_len: int = 70) -> str:
    """Safely format and wrap code snippet lines for PDF code box presentation."""
    if not code:
        return ""
    lines = code.splitlines()
    wrapped_lines = []
    for line in lines:
        if len(line) > max_line_len:
            # Wrap long unbroken strings
            chunks = textwrap.wrap(line, width=max_line_len, break_long_words=True)
            wrapped_lines.extend(chunks if chunks else [line])
        else:
            wrapped_lines.append(line)
    return html.escape("\n".join(wrapped_lines))


def export_pdf_report(report_data: Dict[str, Any]) -> bytes:
    """Generate a multi-page, high-quality PDF security audit report using ReportLab.

    Features:
    - CheckMyCode branding and document layout
    - Two-pass NumberedCanvas for dynamic running headers & 'Page X of Y' footers
    - Executive summary and readiness score visualization
    - KeepTogether protected finding cards preventing awkward page break splits
    - Preserved credential masking with no secrets exposed
    - Trust limitations and verification disclaimers
    """
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.pdfgen import canvas
        from reportlab.platypus import (
            HRFlowable,
            Image,
            KeepTogether,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError as e:
        logger.error("ReportLab library not installed: %s", e)
        raise RuntimeError("ReportLab is required for PDF generation. Install via `pip install reportlab`.") from e

    meta = report_data.get("metadata", {})
    proj = report_data.get("project_summary", {})
    readiness = report_data.get("readiness_evaluation", {})
    findings = report_data.get("findings", [])
    checks = report_data.get("executed_checks", {})
    disclaimer = report_data.get("trust_and_limitations", "")

    proj_name = proj.get("project_name", "Unknown Project")
    raw_date = meta.get("generated_at_utc", datetime.now(timezone.utc).isoformat())
    scan_date = raw_date[:19].replace("T", " ") + " UTC"
    score = float(readiness.get("score", 0.0))
    score_status = readiness.get("status", "Unavailable")

    class NumberedCanvas(canvas.Canvas):
        """Canvas that performs a two-pass calculation for running headers and 'Page X of Y' footers."""

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._saved_page_states = []

        def showPage(self):
            self._saved_page_states.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            num_pages = len(self._saved_page_states)
            for state in self._saved_page_states:
                self.__dict__.update(state)
                self.draw_header_footer(num_pages)
                super().showPage()
            super().save()

        def draw_header_footer(self, page_count):
            self.saveState()
            self.setFont("Helvetica", 8)
            self.setFillColor(colors.HexColor("#64748B"))

            # Header (pages 2+)
            if self._pageNumber > 1:
                self.drawString(40, 750, "CheckMyCode — Security & Deployment Readiness Audit Report")
                self.drawRightString(612 - 40, 750, getattr(self, "_project_name", "Project"))
                self.setStrokeColor(colors.HexColor("#CBD5E1"))
                self.setLineWidth(0.5)
                self.line(40, 742, 612 - 40, 742)

            # Footer (all pages)
            self.setStrokeColor(colors.HexColor("#CBD5E1"))
            self.setLineWidth(0.5)
            self.line(40, 42, 612 - 40, 42)

            self.drawString(40, 30, "CONFIDENTIAL & PROPRIETARY — CHECKMYCODE AUDIT REPORT")
            self.drawRightString(612 - 40, 30, f"Page {self._pageNumber} of {page_count}")
            self.restoreState()

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=40,
        rightMargin=40,
        topMargin=54,
        bottomMargin=54,
    )

    styles = getSampleStyleSheet()

    # Custom Color Palette
    C_PRIMARY = colors.HexColor("#2563EB")
    C_DARK = colors.HexColor("#0F172A")
    C_SLATE = colors.HexColor("#475569")
    C_LIGHT_SLATE = colors.HexColor("#64748B")
    C_BORDER = colors.HexColor("#CBD5E1")
    C_BG_LIGHT = colors.HexColor("#F8FAFC")

    SEV_COLORS = {
        "Critical": (colors.HexColor("#DC2626"), colors.HexColor("#FEE2E2")),
        "High": (colors.HexColor("#EA580C"), colors.HexColor("#FFEDD5")),
        "Medium": (colors.HexColor("#D97706"), colors.HexColor("#FEF3C7")),
        "Low": (colors.HexColor("#2563EB"), colors.HexColor("#DBEAFE")),
    }

    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=C_SLATE,
    )
    h2_style = ParagraphStyle(
        "SectionH2",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=17,
        textColor=C_DARK,
        spaceBefore=14,
        spaceAfter=8,
    )
    body_style = ParagraphStyle(
        "Body",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=C_SLATE,
    )
    body_bold = ParagraphStyle(
        "BodyBold",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=13,
        textColor=C_DARK,
    )
    meta_val_style = ParagraphStyle(
        "MetaVal",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9.5,
        leading=13,
        textColor=C_DARK,
    )
    code_snippet_style = ParagraphStyle(
        "CodeSnippet",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=7.5,
        leading=10.5,
        textColor=colors.HexColor("#1E293B"),
    )

    story = []

    # ── HEADER BRANDING ──
    logo_path = Path(__file__).resolve().parent.parent / "assets" / "checkmycode-logo-light.png"
    if not logo_path.exists():
        logo_path = Path(__file__).resolve().parent.parent / "frontend" / "public" / "logo-light.png"

    if logo_path.exists():
        brand_flowable = Image(str(logo_path), width=145, height=37)
    else:
        brand_flowable = Paragraph(
            "<b>CheckMyCode</b>",
            ParagraphStyle("Brand", fontName="Helvetica-Bold", fontSize=22, textColor=C_PRIMARY),
        )

    header_table_data = [
        [
            brand_flowable,
            Paragraph(
                f"<b>Scan Date:</b> {html.escape(scan_date)}<br/><b>Platform:</b> CheckMyCode v1.1.0",
                ParagraphStyle("HeaderRight", fontName="Helvetica", fontSize=8.5, leading=12, textColor=C_LIGHT_SLATE, alignment=2),
            ),
        ],
        [
            Paragraph("Security Vulnerability & Deployment Readiness Audit", subtitle_style),
            Paragraph(
                "Confidential Developer Audit Report",
                ParagraphStyle("HeaderRight2", fontName="Helvetica-Oblique", fontSize=8, textColor=C_LIGHT_SLATE, alignment=2),
            ),
        ],
    ]
    header_table = Table(header_table_data, colWidths=[340, 192])
    header_table.setStyle(
        TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 0),
        ])
    )
    story.append(header_table)
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1.5, color=C_PRIMARY, spaceAfter=14))

    # ── PROJECT METADATA CARD ──
    langs_str = ", ".join(proj.get("languages", [])) or "None detected"
    frameworks_str = ", ".join(proj.get("frameworks", [])) or "None detected"

    meta_data = [
        [
            Paragraph("Project Name", body_style),
            Paragraph(f"<b>{html.escape(proj_name)}</b>", meta_val_style),
            Paragraph("Files Inspected", body_style),
            Paragraph(f"<b>{proj.get('inspected_files', 0)}</b> of {proj.get('total_files', 0)}", meta_val_style),
        ],
        [
            Paragraph("Languages", body_style),
            Paragraph(f"<b>{html.escape(langs_str)}</b>", meta_val_style),
            Paragraph("Approx. LOC", body_style),
            Paragraph(f"<b>{proj.get('approx_lines_of_code', 0):,}</b>", meta_val_style),
        ],
        [
            Paragraph("Frameworks", body_style),
            Paragraph(f"<b>{html.escape(frameworks_str)}</b>", meta_val_style),
            Paragraph("Manifests", body_style),
            Paragraph(f"<b>{len(proj.get('manifests', []))} file(s)</b>", meta_val_style),
        ],
    ]
    meta_table = Table(meta_data, colWidths=[90, 175, 95, 172])
    meta_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), C_BG_LIGHT),
            ("BOX", (0, 0), (-1, -1), 1, C_BORDER),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, C_BORDER),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ])
    )
    story.append(meta_table)
    story.append(Spacer(1, 14))

    # ── EXECUTIVE SUMMARY & SCORE ──
    story.append(Paragraph("Executive Summary & Readiness Score", h2_style))

    if score >= 90:
        score_color = colors.HexColor("#10B981")
    elif score >= 70:
        score_color = colors.HexColor("#2563EB")
    elif score >= 40:
        score_color = colors.HexColor("#D97706")
    else:
        score_color = colors.HexColor("#DC2626")

    score_card_data = [
        [
            Paragraph(
                f"<font size=28 color='{score_color.hexval()}'><b>{score:.1f}</b></font><font size=12 color='#64748B'> / 100</font><br/>"
                f"<font size=10 color='{score_color.hexval()}'><b>{html.escape(score_status)}</b></font>",
                ParagraphStyle("ScoreBox", fontName="Helvetica", alignment=1, leading=16),
            ),
            Paragraph(
                f"<b>Severity Breakdown:</b><br/>"
                f"&bull; <font color='#DC2626'><b>Critical:</b></font> {readiness.get('critical_issues', 0)} finding(s)<br/>"
                f"&bull; <font color='#EA580C'><b>High Risk:</b></font> {readiness.get('high_issues', 0)} finding(s)<br/>"
                f"&bull; <font color='#D97706'><b>Medium Risk:</b></font> {readiness.get('medium_issues', 0)} finding(s)<br/>"
                f"&bull; <font color='#2563EB'><b>Low Risk:</b></font> {readiness.get('low_issues', 0)} finding(s)",
                body_style,
            ),
            Paragraph(
                f"<b>Scoring Methodology:</b><br/>"
                f"<font size=8 color='#475569'>{html.escape(readiness.get('scoring_methodology', 'Deductions applied from 100 baseline.'))}</font>",
                body_style,
            ),
        ]
    ]
    score_table = Table(score_card_data, colWidths=[140, 160, 232])
    score_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), C_BG_LIGHT),
            ("BOX", (0, 0), (-1, -1), 1, C_BORDER),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, C_BORDER),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ])
    )
    story.append(score_table)
    story.append(Spacer(1, 10))

    # ── EXECUTED SCANNERS TABLE ──
    story.append(
        Paragraph(
            "Security Scanners Executed",
            ParagraphStyle("H3", fontName="Helvetica-Bold", fontSize=10, textColor=C_DARK, spaceBefore=4, spaceAfter=4),
        )
    )
    checks_data = [[Paragraph("<b>Scanner Subsystem</b>", body_style), Paragraph("<b>Status & Findings</b>", body_style)]]
    for chk_name, chk_status in checks.items():
        checks_data.append([
            Paragraph(html.escape(chk_name), body_style),
            Paragraph(f"<b>{html.escape(str(chk_status))}</b>", body_style),
        ])
    checks_table = Table(checks_data, colWidths=[240, 292])
    checks_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
            ("BACKGROUND", (0, 1), (-1, -1), colors.white),
            ("BOX", (0, 0), (-1, -1), 1, C_BORDER),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, C_BORDER),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ])
    )
    story.append(checks_table)
    story.append(Spacer(1, 14))

    # ── DETAILED FINDINGS ──
    story.append(Paragraph(f"Detailed Security Findings ({len(findings)} Total)", h2_style))
    story.append(Paragraph("Each finding reflects an offline static inspection rule match. Secrets are masked with asterisks.", body_style))
    story.append(Spacer(1, 8))

    if not findings:
        empty_card = Table(
            [[
                Paragraph(
                    "<b>No security vulnerabilities or configuration defects detected</b> across the analyzed files. "
                    "Note that clean results reflect only the implemented checks and do not guarantee the absence of all security flaws.",
                    body_style,
                )
            ]],
            colWidths=[532],
        )
        empty_card.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#ECFDF5")),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#6EE7B7")),
                ("TOPPADDING", (0, 0), (-1, -1), 12),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
                ("LEFTPADDING", (0, 0), (-1, -1), 14),
                ("RIGHTPADDING", (0, 0), (-1, -1), 14),
            ])
        )
        story.append(empty_card)
    else:
        for idx, f in enumerate(findings, 1):
            sev = f.get("severity", "Low")
            text_color, bg_color = SEV_COLORS.get(sev, SEV_COLORS["Low"])

            rule_id = f.get("rule_id", "RULE")
            title = f.get("title", "Untitled finding")
            file_p = f.get("file_path", "unknown")
            line_no = f.get("line_number")
            loc_str = f"{file_p}:{line_no}" if line_no is not None else file_p

            expl = f.get("explanation", "")
            impact = f.get("impact", "")
            remed = f.get("remediation", "")
            snippet = f.get("snippet", "")

            # Header row with severity badge and title
            finding_header = [
                [
                    Paragraph(
                        f"<font color='{text_color.hexval()}'><b>[{sev.upper()}]</b></font> <b>{html.escape(rule_id)}</b> — {html.escape(title)}",
                        ParagraphStyle("FindTitle", fontName="Helvetica-Bold", fontSize=9.5, leading=13, textColor=C_DARK),
                    ),
                    Paragraph(
                        f"<font color='#2563EB'><b>{html.escape(loc_str)}</b></font>",
                        ParagraphStyle("FindLoc", fontName="Courier-Bold", fontSize=8, leading=11, alignment=2),
                    ),
                ]
            ]
            f_hdr_table = Table(finding_header, colWidths=[360, 162])
            f_hdr_table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), bg_color),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ])
            )

            # Details body
            body_rows = [
                [Paragraph("<b>Explanation:</b>", body_bold), Paragraph(html.escape(expl), body_style)],
            ]
            if impact:
                body_rows.append([Paragraph("<b>Impact:</b>", body_bold), Paragraph(html.escape(impact), body_style)])
            if remed:
                body_rows.append([
                    Paragraph("<b>Remediation:</b>", body_bold),
                    Paragraph(f"<font color='#0284C7'><b>{html.escape(remed)}</b></font>", body_style),
                ])
            if snippet:
                formatted_snippet = _wrap_snippet(snippet)
                body_rows.append([
                    Paragraph("<b>Code Snippet:</b>", body_bold),
                    Paragraph(f"<font color='#1E293B'>{formatted_snippet}</font>", code_snippet_style),
                ])

            f_body_table = Table(body_rows, colWidths=[90, 432])
            f_body_table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), colors.white),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LINEBELOW", (0, 0), (-1, -2), 0.5, colors.HexColor("#F1F5F9")),
                ])
            )

            # Outer wrapper table for border & KeepTogether to avoid awkward page break cuts
            finding_block = Table([[f_hdr_table], [f_body_table]], colWidths=[532])
            finding_block.setStyle(
                TableStyle([
                    ("BOX", (0, 0), (-1, -1), 1, C_BORDER),
                    ("TOPPADDING", (0, 0), (-1, -1), 0),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
                    ("LEFTPADDING", (0, 0), (-1, -1), 0),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ])
            )

            story.append(KeepTogether([finding_block, Spacer(1, 8)]))

    # ── DISCLAIMER & TRUST NOTICE ──
    story.append(Spacer(1, 10))
    disclaimer_p = Paragraph(
        f"<b>Security Limitations &amp; Verification Disclaimer:</b><br/>"
        f"{html.escape(disclaimer)}",
        ParagraphStyle("Disclaimer", fontName="Helvetica", fontSize=8, leading=11, textColor=C_LIGHT_SLATE),
    )
    disclaimer_box = Table([[disclaimer_p]], colWidths=[532])
    disclaimer_box.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), C_BG_LIGHT),
            ("BOX", (0, 0), (-1, -1), 0.75, C_BORDER),
            ("LINEBEFORE", (0, 0), (0, -1), 3, C_PRIMARY),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ])
    )
    story.append(KeepTogether([disclaimer_box]))

    # Set project name on canvas for running header
    def make_canvas(*args, **kwargs):
        c = NumberedCanvas(*args, **kwargs)
        c._project_name = proj_name
        return c

    doc.build(story, canvasmaker=make_canvas)
    return buffer.getvalue()
