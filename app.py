from __future__ import annotations

import base64
from datetime import datetime, timezone
import html
import io
import json
import logging
from pathlib import Path
import re
import tempfile
from typing import Any, Dict, List, Optional

import streamlit as st

from modules.archive_handler import cleanup_directory, extract_archive_safely
from modules.configuration_scanner import scan_project_configuration
from modules.dependency_scanner import scan_project_dependencies
from modules.project_profiler import profile_project
from modules.report_generator import (
    export_html_report,
    export_json_report,
    generate_audit_report_dict,
)
from modules.risk_scorer import calculate_risk_score
from modules.secret_scanner import scan_project_secrets
from modules.security_scanner import scan_project_security

# ---------------------------------------------------------------------------
# LOGGING & ASSET PATHS
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("CheckMyCode")

ASSETS_DIR = Path(__file__).parent / "assets"
LOGO_PNG_PATH = ASSETS_DIR / "checkmycode-logo.png"
ICON_PNG_PATH = ASSETS_DIR / "checkmycode-icon.png"
FAVICON_PATH = ASSETS_DIR / "favicon.png"
SAMPLE_ZIP_PATH = Path(__file__).parent / "sample_data" / "sample_project.zip"
FEEDBACK_FILE = Path(__file__).parent / "feedback_submissions.json"

# ---------------------------------------------------------------------------
# PAGE CONFIG
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="CheckMyCode — Find the risks. Fix them before you ship.",
    page_icon=str(FAVICON_PATH) if FAVICON_PATH.exists() else "🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)


# ---------------------------------------------------------------------------
# ASSET HELPERS
# ---------------------------------------------------------------------------
def _image_data_uri(path: Path) -> str:
    if not path.exists():
        return ""
    suffix = path.suffix.lower().replace(".", "")
    mime = "image/png" if suffix == "png" else "image/svg+xml" if suffix == "svg" else "image/jpeg"
    return f"data:{mime};base64,{base64.b64encode(path.read_bytes()).decode()}"


LOGO_URI = _image_data_uri(LOGO_PNG_PATH)
ICON_URI = _image_data_uri(ICON_PNG_PATH)


# ---------------------------------------------------------------------------
# SESSION STATE INITIALIZATION
# ---------------------------------------------------------------------------
for _key, _default in [
    ("scan_results", None),
    ("active_project_name", ""),
    ("temp_scan_dir", None),
    ("current_page", "home"),  # "home" | "scan" | "results" | "terms" | "privacy"
    ("scan_running", False),
    ("feedback_submitted", False),
]:
    if _key not in st.session_state:
        st.session_state[_key] = _default


def _reset_scan() -> None:
    if st.session_state.get("temp_scan_dir"):
        cleanup_directory(st.session_state["temp_scan_dir"])
        st.session_state["temp_scan_dir"] = None
    st.session_state["scan_results"] = None
    st.session_state["active_project_name"] = ""
    st.session_state["feedback_submitted"] = False


def _run_scan(archive_source: Any, project_name: str, prefs: Dict[str, bool]) -> bool:
    """Extract archive safely, execute scanners, and store structured results."""
    if st.session_state.get("temp_scan_dir"):
        cleanup_directory(st.session_state["temp_scan_dir"])

    temp_dir = Path(tempfile.mkdtemp(prefix="cmc_scan_"))
    st.session_state["temp_scan_dir"] = temp_dir

    success, err_msg, meta = extract_archive_safely(archive_source, temp_dir)
    if not success:
        st.error(f"Archive validation failed: {err_msg}")
        cleanup_directory(temp_dir)
        st.session_state["temp_scan_dir"] = None
        return False

    profile = profile_project(temp_dir)
    profile["project_name"] = project_name

    all_findings: List[Dict[str, Any]] = []
    statuses: Dict[str, str] = {}

    if prefs.get("secrets", True):
        sf = scan_project_secrets(temp_dir, profile["inspected_file_paths"])
        all_findings.extend(sf)
        statuses["Secret Detection"] = f"{len(sf)} finding(s)"
    else:
        statuses["Secret Detection"] = "Skipped"

    if prefs.get("code_sec", True):
        cf = scan_project_security(temp_dir, profile["inspected_file_paths"])
        all_findings.extend(cf)
        statuses["Code Security Analysis"] = f"{len(cf)} finding(s)"
    else:
        statuses["Code Security Analysis"] = "Skipped"

    if prefs.get("deps", True):
        df, ds = scan_project_dependencies(temp_dir, profile["manifests"])
        all_findings.extend(df)
        pkgs = ds.get("total_packages_checked", 0)
        statuses["Dependency Advisory Scanner"] = f"{pkgs} package(s) checked, {len(df)} finding(s)"
    else:
        statuses["Dependency Advisory Scanner"] = "Skipped"

    if prefs.get("config", True):
        gf = scan_project_configuration(
            temp_dir, profile["inspected_file_paths"] + profile["configs"]
        )
        all_findings.extend(gf)
        statuses["Deployment Configuration Scanner"] = f"{len(gf)} finding(s)"
    else:
        statuses["Deployment Configuration Scanner"] = "Skipped"

    score_data = calculate_risk_score(all_findings, profile["inspected_files"])

    st.session_state["scan_results"] = {
        "profile": profile,
        "findings": all_findings,
        "score_data": score_data,
        "check_statuses": statuses,
    }
    st.session_state["active_project_name"] = project_name
    st.session_state["feedback_submitted"] = False
    return True


def _save_feedback(payload: Dict[str, Any]) -> bool:
    """Persist feedback to a local JSON storage file."""
    try:
        data = []
        if FEEDBACK_FILE.exists():
            try:
                data = json.loads(FEEDBACK_FILE.read_text(encoding="utf-8"))
                if not isinstance(data, list):
                    data = []
            except Exception:
                data = []
        data.append(payload)
        FEEDBACK_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return True
    except Exception as e:
        logger.error(f"Failed to persist feedback: {e}")
        return False


# ---------------------------------------------------------------------------
# GLOBAL CSS — Blue & Black Developer-Tool Theme
# Palette:
#   Main bg: #080B12 | Secondary bg: #0D1424 | Card bg: #111B2D
#   Elevated: #17243A | Border: #24334B | Primary Blue: #3478F6
#   Cyan: #22D3EE | Text: #F5F7FB | Muted: #718096 | Sec Text: #A7B3C8
# ---------------------------------------------------------------------------
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    color: #F5F7FB;
    background-color: #080B12;
}

.main .block-container {
    padding: 0 1.5rem 3rem 1.5rem;
    max-width: 1220px;
}

/* Hide default streamlit chrome */
section[data-testid="stSidebar"] { display: none; }
button[data-testid="stSidebarCollapseButton"],
button[data-testid="stSidebarExpandButton"] { display: none !important; }
#MainMenu { visibility: hidden; }
header[data-testid="stHeader"] { background: transparent; height: 0 !important; min-height: 0 !important; }
footer { visibility: hidden; }

/* ── Top Header ────────────────────────────────────────── */
.cmc-topbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.9rem 0;
    border-bottom: 1px solid #24334B;
    margin-bottom: 1.5rem;
}
.cmc-topbar-brand {
    display: flex;
    align-items: center;
    gap: 12px;
    text-decoration: none;
}
.cmc-topbar-brand img {
    height: 34px;
    width: auto;
    object-fit: contain;
}
.cmc-brand-text {
    font-size: 1.35rem;
    font-weight: 800;
    color: #F5F7FB;
    letter-spacing: -0.02em;
}
.cmc-brand-text span {
    color: #3478F6;
}
.cmc-badge-pill {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.72rem;
    font-weight: 600;
    padding: 4px 12px;
    border-radius: 20px;
    letter-spacing: 0.04em;
    background: #111B2D;
    border: 1px solid #24334B;
    color: #A7B3C8;
}
.cmc-badge-active {
    background: rgba(34, 211, 238, 0.1);
    border-color: rgba(34, 211, 238, 0.35);
    color: #22D3EE;
}

/* ── Hero section ──────────────────────────────────────── */
.cmc-hero {
    padding: 3.5rem 1rem 2.5rem 1rem;
    text-align: center;
    max-width: 820px;
    margin: 0 auto;
}
.cmc-hero-tagline {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem;
    font-weight: 600;
    color: #22D3EE;
    background: rgba(34, 211, 238, 0.08);
    border: 1px solid rgba(34, 211, 238, 0.25);
    border-radius: 20px;
    padding: 5px 14px;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    margin-bottom: 1.2rem;
}
.cmc-hero-h1 {
    font-size: 3.1rem;
    font-weight: 800;
    color: #F5F7FB;
    line-height: 1.15;
    letter-spacing: -0.035em;
    margin-bottom: 1.1rem;
}
.cmc-hero-h1 span {
    color: #3478F6;
}
.cmc-hero-sub {
    font-size: 1.08rem;
    color: #A7B3C8;
    line-height: 1.65;
    max-width: 660px;
    margin: 0 auto 2.2rem auto;
}

/* ── Cards & Surfaces ──────────────────────────────────── */
.cmc-card {
    background: #111B2D;
    border: 1px solid #24334B;
    border-radius: 10px;
    padding: 1.3rem 1.4rem;
    transition: border-color 0.18s ease, transform 0.18s ease;
}
.cmc-card:hover {
    border-color: #3478F6;
}
.cmc-card-elevated {
    background: #17243A;
    border: 1px solid #24334B;
    border-radius: 10px;
    padding: 1.3rem 1.4rem;
}
.cmc-card-accent {
    background: #111B2D;
    border: 1px solid #24334B;
    border-left: 3px solid #3478F6;
    border-radius: 10px;
    padding: 1.2rem 1.3rem;
}

/* ── Buttons ───────────────────────────────────────────── */
div.stButton > button {
    border-radius: 8px;
    font-weight: 600;
    font-size: 0.88rem;
    padding: 0.55rem 1.3rem;
    border: 1px solid #24334B;
    background: #111B2D;
    color: #F5F7FB;
    transition: all 0.18s ease;
}
div.stButton > button:hover {
    border-color: #3478F6;
    background: #17243A;
    color: #FFFFFF;
}
div.stButton > button[kind="primary"],
div.stButton > button[data-testid="stBaseButton-primary"] {
    background: #3478F6 !important;
    border-color: #3478F6 !important;
    color: #FFFFFF !important;
    font-weight: 700 !important;
    box-shadow: 0 4px 14px rgba(52, 120, 246, 0.3);
}
div.stButton > button[kind="primary"]:hover,
div.stButton > button[data-testid="stBaseButton-primary"]:hover {
    background: #2563EB !important;
    border-color: #2563EB !important;
    box-shadow: 0 6px 18px rgba(52, 120, 246, 0.45);
}

div.stDownloadButton > button {
    border-radius: 8px;
    font-weight: 600;
    font-size: 0.85rem;
    padding: 0.55rem 1.2rem;
    border: 1px solid #24334B;
    background: #111B2D;
    color: #F5F7FB;
    transition: all 0.18s ease;
}
div.stDownloadButton > button:hover {
    border-color: #3478F6;
    background: #17243A;
}
div.stDownloadButton > button[kind="primary"],
div.stDownloadButton > button[data-testid="stBaseButton-primary"] {
    background: #3478F6 !important;
    border-color: #3478F6 !important;
    color: #FFFFFF !important;
}

/* ── File Uploader ─────────────────────────────────────── */
div[data-testid="stFileUploaderDropzone"] {
    background: #111B2D !important;
    border: 2px dashed #24334B !important;
    border-radius: 10px !important;
    padding: 2rem 1.5rem !important;
}
div[data-testid="stFileUploaderDropzone"]:hover {
    border-color: #3478F6 !important;
}

/* ── Metrics ───────────────────────────────────────────── */
.cmc-metric {
    background: #111B2D;
    border: 1px solid #24334B;
    border-radius: 10px;
    padding: 1.1rem 1.25rem;
    display: flex;
    flex-direction: column;
    min-height: 105px;
}
.cmc-metric-label {
    font-size: 0.68rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: #718096;
    font-weight: 700;
    margin-bottom: 0.35rem;
}
.cmc-metric-value {
    font-family: 'JetBrains Mono', monospace;
    font-size: 1.95rem;
    font-weight: 700;
    color: #F5F7FB;
    line-height: 1.1;
}
.cmc-metric-sub {
    font-size: 0.72rem;
    color: #718096;
    margin-top: auto;
    padding-top: 0.4rem;
}

/* ── Severity Badges ───────────────────────────────────── */
.cmc-badge {
    display: inline-flex;
    align-items: center;
    font-size: 0.68rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    padding: 3px 8px;
    border-radius: 4px;
    line-height: 1.2;
}
.sev-critical {
    background: rgba(255, 77, 94, 0.15);
    color: #FF4D5E;
    border: 1px solid rgba(255, 77, 94, 0.35);
}
.sev-high {
    background: rgba(255, 138, 61, 0.15);
    color: #FF8A3D;
    border: 1px solid rgba(255, 138, 61, 0.35);
}
.sev-medium {
    background: rgba(245, 196, 81, 0.15);
    color: #F5C451;
    border: 1px solid rgba(245, 196, 81, 0.35);
}
.sev-low {
    background: rgba(79, 156, 249, 0.15);
    color: #4F9CF9;
    border: 1px solid rgba(79, 156, 249, 0.35);
}

/* ── Finding Row / Detail ──────────────────────────────── */
.cmc-finding-header {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
    margin-bottom: 0.6rem;
}
.cmc-rule-pill {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.68rem;
    background: #0D1424;
    color: #A7B3C8;
    padding: 2px 7px;
    border-radius: 4px;
    border: 1px solid #24334B;
}
.cmc-cat-label {
    font-size: 0.72rem;
    color: #718096;
}
.cmc-finding-body {
    font-size: 0.84rem;
    color: #A7B3C8;
    line-height: 1.6;
}
.cmc-finding-body strong {
    color: #F5F7FB;
}
.cmc-finding-fix {
    color: #22D3EE;
    font-weight: 500;
}
.cmc-finding-loc {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem;
    color: #3478F6;
    margin-top: 0.4rem;
}

/* ── Expanders ─────────────────────────────────────────── */
details[data-testid="stExpander"] {
    background: #111B2D !important;
    border: 1px solid #24334B !important;
    border-radius: 8px !important;
    margin-bottom: 0.5rem;
}
details[data-testid="stExpander"] summary {
    font-size: 0.86rem;
    font-weight: 600;
    color: #F5F7FB;
    padding: 0.75rem 1rem;
}
details[data-testid="stExpander"][open] summary {
    border-bottom: 1px solid #24334B;
}

/* ── Form Inputs ───────────────────────────────────────── */
div[data-baseweb="select"] > div,
div[data-baseweb="input"] > div,
textarea {
    background-color: #0D1424 !important;
    border-color: #24334B !important;
    color: #F5F7FB !important;
    border-radius: 6px !important;
}
div[data-testid="stCheckbox"] label {
    color: #A7B3C8 !important;
    font-size: 0.84rem !important;
}

/* ── Check Status Item ─────────────────────────────────── */
.cmc-check-item {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 0.82rem;
    color: #A7B3C8;
    padding: 6px 0;
}
.cmc-check-dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    flex-shrink: 0;
}
.cmc-check-dot-ok {
    background: #22D3EE;
    box-shadow: 0 0 6px rgba(34, 211, 238, 0.4);
}
.cmc-check-dot-skip {
    background: #718096;
}

/* ── Section Label ─────────────────────────────────────── */
.cmc-section-label {
    font-size: 0.72rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: #718096;
    margin-bottom: 0.8rem;
    margin-top: 0.6rem;
}

/* ── Score Ring ─────────────────────────────────────────── */
.cmc-score-ring {
    position: relative;
    width: 105px;
    height: 105px;
    flex-shrink: 0;
}
.cmc-score-ring svg { transform: rotate(-90deg); }
.cmc-score-ring .score-num {
    position: absolute;
    inset: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: 'JetBrains Mono', monospace;
    font-size: 1.6rem;
    font-weight: 800;
    color: #F5F7FB;
}

/* ── Footer ────────────────────────────────────────────── */
.cmc-footer {
    border-top: 1px solid #24334B;
    margin-top: 4rem;
    padding-top: 1.8rem;
    padding-bottom: 1.5rem;
    font-size: 0.8rem;
    color: #718096;
}
.cmc-footer-grid {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    flex-wrap: wrap;
    gap: 1.5rem;
    margin-bottom: 1.2rem;
}
.cmc-footer-brand {
    max-width: 320px;
}
.cmc-footer-links {
    display: flex;
    gap: 1.8rem;
    flex-wrap: wrap;
}
.cmc-footer-copy {
    border-top: 1px solid #17243A;
    padding-top: 1rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 10px;
    font-size: 0.74rem;
}

/* ── Legal Page Styles ─────────────────────────────────── */
.cmc-legal-box {
    background: #111B2D;
    border: 1px solid #24334B;
    border-radius: 10px;
    padding: 2.2rem;
    max-width: 900px;
    margin: 0 auto;
    line-height: 1.7;
    font-size: 0.88rem;
    color: #A7B3C8;
}
.cmc-legal-box h2 {
    color: #F5F7FB;
    font-size: 1.2rem;
    font-weight: 700;
    margin-top: 1.8rem;
    margin-bottom: 0.6rem;
    border-bottom: 1px solid #24334B;
    padding-bottom: 0.4rem;
}
.cmc-legal-box h2:first-of-type {
    margin-top: 0;
}
.cmc-legal-box strong {
    color: #F5F7FB;
}
.cmc-legal-box ul {
    padding-left: 1.3rem;
    margin-top: 0.4rem;
    margin-bottom: 1rem;
}
.cmc-legal-box li {
    margin-bottom: 0.35rem;
}

/* ── Feedback Container ────────────────────────────────── */
.cmc-feedback-box {
    background: #111B2D;
    border: 1px solid #24334B;
    border-radius: 10px;
    padding: 1.6rem;
    margin-top: 2.5rem;
}
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# NAVIGATION HANDLERS
# ---------------------------------------------------------------------------
def set_page(page_name: str) -> None:
    st.session_state["current_page"] = page_name


# ---------------------------------------------------------------------------
# GLOBAL HEADER
# ---------------------------------------------------------------------------
def render_header():
    has_results = st.session_state["scan_results"] is not None
    proj_name = st.session_state.get("active_project_name", "")
    page = st.session_state.get("current_page", "home")

    logo_markup = f'<img src="{LOGO_URI}" alt="CheckMyCode" />' if LOGO_URI else '<div class="cmc-brand-text">Check<span>MyCode</span></div>'

    status_markup = (
        f'<span class="cmc-badge-pill cmc-badge-active">● {html.escape(proj_name)}</span>'
        if has_results
        else '<span class="cmc-badge-pill">● Ready</span>'
    )

    st.markdown(f"""
    <div class="cmc-topbar">
        <div class="cmc-topbar-brand">
            {logo_markup}
        </div>
        <div>{status_markup}</div>
    </div>
    """, unsafe_allow_html=True)

    # Clean sub-navigation when away from home or when results exist
    nav_cols = st.columns([1, 1, 1, 4])
    with nav_cols[0]:
        if st.button("🏠 Home", use_container_width=True):
            set_page("home")
            st.rerun()
    with nav_cols[1]:
        if st.button("🚀 Scanner", use_container_width=True):
            set_page("scan")
            st.rerun()
    with nav_cols[2]:
        if has_results:
            if st.button("📊 Results", use_container_width=True):
                set_page("results")
                st.rerun()


# ---------------------------------------------------------------------------
# GLOBAL FOOTER
# ---------------------------------------------------------------------------
def render_footer():
    st.markdown("""
    <div class="cmc-footer">
        <div class="cmc-footer-grid">
            <div class="cmc-footer-brand">
                <div style="font-weight: 700; color: #F5F7FB; font-size: 0.95rem; margin-bottom: 0.3rem;">
                    Check<span style="color:#3478F6;">MyCode</span>
                </div>
                <div style="line-height: 1.5; color: #718096; font-size: 0.78rem;">
                    Find the risks. Fix them before you ship. Developer-focused static security and deployment readiness analysis.
                </div>
            </div>
            <div class="cmc-footer-links">
                <div>
                    <div style="font-weight: 600; color: #F5F7FB; font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 0.5rem;">Platform</div>
                    <div style="font-size: 0.78rem; color: #A7B3C8; line-height: 1.8;">
                        Offline Static Analysis<br>
                        Rule-Based CVE Checks<br>
                        Exportable Reports
                    </div>
                </div>
                <div>
                    <div style="font-weight: 600; color: #F5F7FB; font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 0.5rem;">Security Engine</div>
                    <div style="font-size: 0.78rem; color: #A7B3C8; line-height: 1.8;">
                        Zero Code Execution<br>
                        Air-Gapped Operation<br>
                        No Third-Party AI APIs
                    </div>
                </div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Footer interactive links as a button bar
    fc1, fc2, fc3, fc4, fc5 = st.columns([1.5, 1.5, 1.5, 1.5, 3])
    with fc1:
        if st.button("Scanner", key="ft_scan"):
            set_page("scan")
            st.rerun()
    with fc2:
        if st.button("How It Works", key="ft_hiw"):
            set_page("home")
            st.rerun()
    with fc3:
        if st.button("Terms & Conditions", key="ft_terms"):
            set_page("terms")
            st.rerun()
    with fc4:
        if st.button("Privacy Policy", key="ft_privacy"):
            set_page("privacy")
            st.rerun()

    st.markdown("""
    <div class="cmc-footer-copy">
        <div>&copy; CheckMyCode &middot; Built on OpenGuard Core Engine &middot; Clean Developer Tools</div>
        <div>Rule-based static analysis &middot; Not a substitute for formal manual penetration testing</div>
    </div>
    """, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# VIEW: HOMEPAGE
# ---------------------------------------------------------------------------
def render_homepage():
    st.markdown("""
    <div class="cmc-hero">
        <div class="cmc-hero-tagline">⚡ Developer-Focused Security & Readiness</div>
        <div class="cmc-hero-h1">Find the risks.<br><span>Fix them before you ship.</span></div>
        <div class="cmc-hero-sub">
            Check your project for potential security vulnerabilities, exposed secrets,
            risky configurations, and other issues before deployment — entirely offline,
            with zero code execution.
        </div>
    </div>
    """, unsafe_allow_html=True)

    c1, c2, c3 = st.columns([1.8, 1.4, 1.8])
    with c2:
        if st.button("🚀  Scan My Project", type="primary", use_container_width=True):
            set_page("scan")
            st.rerun()

    st.markdown('<div style="height: 2.2rem;"></div>', unsafe_allow_html=True)

    # 3-Step How It Works
    st.markdown('<div class="cmc-section-label">How CheckMyCode Works</div>', unsafe_allow_html=True)
    s1, s2, s3 = st.columns(3)
    steps = [
        ("01", "#3478F6", "1. Upload Your Project", "Submit your project ZIP archive. The file is validated and unpacked into an isolated, temporary sandbox directory."),
        ("02", "#22D3EE", "2. Analyze Its Contents", "Our rule-based engine inspects manifests, configs, and source files for known CVEs, secrets, and dangerous patterns."),
        ("03", "#F5C451", "3. Review Findings & Fixes", "Explore categorized findings with line numbers, risk explanations, and copy-ready remediation instructions."),
    ]
    for col, (num, color, title, desc) in zip([s1, s2, s3], steps):
        with col:
            st.markdown(f"""
            <div class="cmc-card" style="height: 100%;">
                <div style="font-family:'JetBrains Mono',monospace;font-size:0.78rem;font-weight:700;color:{color};margin-bottom:0.4rem;">{num}</div>
                <div style="font-weight:600;font-size:0.95rem;color:#F5F7FB;margin-bottom:0.35rem;">{title}</div>
                <div style="font-size:0.8rem;color:#A7B3C8;line-height:1.6;">{desc}</div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown('<div style="height: 2rem;"></div>', unsafe_allow_html=True)

    # Feature capabilities section (genuinely implemented capabilities only)
    st.markdown('<div class="cmc-section-label">Genuinely Implemented Detection Capabilities</div>', unsafe_allow_html=True)
    f1, f2, f3, f4 = st.columns(4)
    features = [
        ("Secret Detection", "High-entropy and pattern matching for AWS keys, GitHub tokens, database URIs, private keys, and passwords.", "🔑"),
        ("Code Security", "AST and static regex checks for eval(), exec(), shell=True, disabled SSL verification, and debug flags.", "🔒"),
        ("Dependency Advisories", "Checks requirements.txt and package.json against a bundled database of known CVE advisories and unpinned packages.", "📦"),
        ("Deployment Readiness", "Scans Dockerfiles and docker-compose files for root execution, :latest tags, privileged containers, and unignored .env files.", "🐳"),
    ]
    for col, (title, desc, icon) in zip([f1, f2, f3, f4], features):
        with col:
            st.markdown(f"""
            <div class="cmc-card-elevated" style="height: 100%;">
                <div style="font-size:1.4rem;margin-bottom:0.4rem;">{icon}</div>
                <div style="font-weight:600;font-size:0.9rem;color:#F5F7FB;margin-bottom:0.3rem;">{title}</div>
                <div style="font-size:0.78rem;color:#A7B3C8;line-height:1.55;">{desc}</div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown('<div style="height: 2rem;"></div>', unsafe_allow_html=True)

    # Realistic limitations notice
    st.markdown("""
    <div class="cmc-card-accent">
        <div style="font-weight:600;font-size:0.88rem;color:#F5F7FB;margin-bottom:0.25rem;">Trust & Verification Boundary</div>
        <div style="font-size:0.8rem;color:#A7B3C8;line-height:1.6;">
            CheckMyCode identifies potential issues through static rule-based checks. It is designed to catch common deployment blunders,
            hardcoded credentials, and known dependency advisories. It does <strong>not</strong> execute your code, emulate runtime conditions,
            or replace a qualified professional security audit or comprehensive penetration test.
        </div>
    </div>
    """, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# VIEW: SCAN PROJECT
# ---------------------------------------------------------------------------
def render_scan_page():
    st.markdown("""
    <div style="margin-bottom: 1.2rem;">
        <div style="font-size: 1.3rem; font-weight: 700; color: #F5F7FB;">Scan Your Project</div>
        <div style="font-size: 0.82rem; color: #A7B3C8; margin-top: 0.2rem;">
            Upload a ZIP archive of your source code. All analysis is performed locally in an isolated workspace.
        </div>
    </div>
    """, unsafe_allow_html=True)

    col_upload, col_sample = st.columns([3, 2], gap="large")

    with col_upload:
        st.markdown("""
        <div class="cmc-card" style="margin-bottom: 0.8rem;">
            <div style="font-weight: 600; font-size: 0.95rem; color: #F5F7FB; margin-bottom: 0.25rem;">
                Project Archive Upload
            </div>
            <div style="font-size: 0.78rem; color: #718096;">
                Supported: Python, JavaScript/TypeScript, Dockerfile, docker-compose &middot; Max 50 MB
            </div>
        </div>
        """, unsafe_allow_html=True)

        uploaded_zip = st.file_uploader(
            "Choose a ZIP file",
            type=["zip"],
            help="Upload your project code bundled as a .zip file (up to 50MB)",
            label_visibility="collapsed",
        )

        st.markdown('<div class="cmc-section-label" style="margin-top: 1rem;">Active Scanners</div>', unsafe_allow_html=True)
        chk_sec = st.checkbox("Secret Detection (API keys, tokens, credentials, private keys)", value=True, key="pref_sec")
        chk_code = st.checkbox("Code Security Patterns (eval, subprocess shell, disabled TLS, debug flags)", value=True, key="pref_code")
        chk_deps = st.checkbox("Dependency CVE Advisories (requirements.txt, package.json)", value=True, key="pref_deps")
        chk_cfg = st.checkbox("Deployment Configurations (Dockerfile root, privileged compose, committed .env)", value=True, key="pref_cfg")

        if uploaded_zip is not None:
            file_mb = uploaded_zip.size / (1024 * 1024)
            st.markdown(
                f'<div style="font-size:0.8rem;color:#22D3EE;margin:0.8rem 0;padding:0.6rem 0.9rem;'
                f'background:rgba(34,211,238,0.06);border:1px solid rgba(34,211,238,0.2);border-radius:6px;">'
                f'Selected file: <strong>{html.escape(uploaded_zip.name)}</strong> ({file_mb:.2f} MB)'
                f'</div>',
                unsafe_allow_html=True,
            )

            # Prevent double click while scanning
            if st.button("🔍  Run Security Scan", type="primary", use_container_width=True):
                prefs = {"secrets": chk_sec, "code_sec": chk_code, "deps": chk_deps, "config": chk_cfg}
                proj_name = uploaded_zip.name.replace(".zip", "")
                with st.spinner("Analyzing project in isolated sandbox..."):
                    if _run_scan(uploaded_zip, proj_name, prefs):
                        set_page("results")
                        st.rerun()

    with col_sample:
        st.markdown("""
        <div class="cmc-card-accent">
            <div style="font-weight: 600; font-size: 0.95rem; color: #F5F7FB; margin-bottom: 0.3rem;">
                🧪 Try the Built-in Sample Project
            </div>
            <div style="font-size: 0.8rem; color: #A7B3C8; margin-bottom: 0.8rem; line-height: 1.5;">
                Test CheckMyCode instantly with a realistic microservice containing deliberate security defects:
            </div>
            <ul style="font-size: 0.78rem; color: #A7B3C8; line-height: 1.7; padding-left: 1.1rem; margin: 0 0 1rem 0;">
                <li>Hardcoded OpenAI and AWS credentials</li>
                <li>Insecure subprocess invocation with shell=True</li>
                <li>Vulnerable requests and lodash package versions</li>
                <li>Dockerfile running as root user with :latest tag</li>
                <li>Missing .env pattern in .gitignore</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

        if st.button("⚡ Load & Scan Sample Project", use_container_width=True):
            if SAMPLE_ZIP_PATH.exists():
                prefs = {"secrets": True, "code_sec": True, "deps": True, "config": True}
                with st.spinner("Extracting and analyzing sample project..."):
                    if _run_scan(SAMPLE_ZIP_PATH, "sample_microservice", prefs):
                        set_page("results")
                        st.rerun()
            else:
                st.error("Sample project ZIP not found on server.")

        st.markdown('<div style="height: 1rem;"></div>', unsafe_allow_html=True)

        st.markdown("""
        <div class="cmc-card" style="padding: 1.1rem;">
            <div style="font-weight: 600; font-size: 0.82rem; color: #F5F7FB; margin-bottom: 0.35rem;">
                🛡️ Security & Privacy Guarantee
            </div>
            <div style="font-size: 0.76rem; color: #718096; line-height: 1.6;">
                Files are decompressed exclusively to a random volatile temp directory, parsed statically,
                and removed when reset. No code is compiled, run, or sent across network APIs.
            </div>
        </div>
        """, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# VIEW: SCAN RESULTS & REPORTS
# ---------------------------------------------------------------------------
def render_results_page():
    if st.session_state["scan_results"] is None:
        st.info("No scan results currently available. Please upload a project to inspect.")
        if st.button("Go to Scanner"):
            set_page("scan")
            st.rerun()
        return

    data = st.session_state["scan_results"]
    profile = data["profile"]
    findings = data["findings"]
    score_data = data["score_data"]
    statuses = data["check_statuses"]

    # Top action bar
    top_c1, top_c2 = st.columns([4, 1])
    with top_c1:
        st.markdown(
            f'<div style="font-size:1.35rem;font-weight:800;color:#F5F7FB;margin-bottom:0.15rem;">'
            f'Audit Report: <span style="font-family:\'JetBrains Mono\',monospace;color:#3478F6;">'
            f'{html.escape(profile["project_name"])}</span></div>',
            unsafe_allow_html=True,
        )
        lang_str = ", ".join(profile["languages"]) or "None identified"
        st.markdown(
            f'<div style="font-size:0.8rem;color:#718096;margin-bottom:1.2rem;">'
            f'{profile["inspected_files"]} files inspected &middot; ~{profile["approx_loc"]:,} lines of code &middot; Languages: {lang_str}'
            f"</div>",
            unsafe_allow_html=True,
        )
    with top_c2:
        if st.button("🔄 New Scan", use_container_width=True):
            _reset_scan()
            set_page("scan")
            st.rerun()

    # Score ring + KPI metrics
    score = score_data["score"]
    pct = max(0.0, min(1.0, score / 100))
    circ = 2 * 3.14159 * 42
    dash = circ * pct
    gap = circ - dash

    score_color = (
        "#22D3EE"
        if score >= 90
        else "#3478F6"
        if score >= 70
        else "#F5C451"
        if score >= 40
        else "#FF4D5E"
    )

    mc1, mc2 = st.columns([1, 3])
    with mc1:
        st.markdown(f"""
        <div class="cmc-metric" style="align-items:center;justify-content:center;padding:1.4rem;">
            <div class="cmc-score-ring">
                <svg viewBox="0 0 100 100" width="105" height="105">
                    <circle cx="50" cy="50" r="42" fill="none" stroke="#24334B" stroke-width="7"/>
                    <circle cx="50" cy="50" r="42" fill="none" stroke="{score_color}" stroke-width="7"
                            stroke-dasharray="{dash:.1f} {gap:.1f}" stroke-linecap="round"/>
                </svg>
                <div class="score-num" style="color:{score_color};">{int(score)}</div>
            </div>
            <div style="text-align:center;margin-top:0.4rem;">
                <span style="font-size:0.75rem;font-weight:700;color:{score_color};background:rgba(255,255,255,0.04);padding:3px 10px;border-radius:12px;border:1px solid #24334B;">
                    {html.escape(score_data["status"])}
                </span>
            </div>
        </div>
        """, unsafe_allow_html=True)

    with mc2:
        k1, k2, k3, k4 = st.columns(4)
        kpi_data = [
            ("Critical", score_data["critical_count"], "#FF4D5E", "-25 pts each"),
            ("High", score_data["high_count"], "#FF8A3D", "-12 pts each"),
            ("Medium", score_data["medium_count"], "#F5C451", "-5 pts each"),
            ("Low / Info", score_data["low_count"], "#4F9CF9", "-2 pts each"),
        ]
        for col, (label, count, color, sub) in zip([k1, k2, k3, k4], kpi_data):
            with col:
                st.markdown(f"""
                <div class="cmc-metric">
                    <div class="cmc-metric-label">{label}</div>
                    <div class="cmc-metric-value" style="color:{color};">{count}</div>
                    <div class="cmc-metric-sub">{sub}</div>
                </div>
                """, unsafe_allow_html=True)

    st.markdown('<div style="height: 0.8rem;"></div>', unsafe_allow_html=True)

    # Scanners executed summary
    status_items = ""
    for scanner_name, status_text in statuses.items():
        is_ok = "Skipped" not in status_text
        dot_cls = "cmc-check-dot-ok" if is_ok else "cmc-check-dot-skip"
        status_items += f"""
        <div class="cmc-check-item">
            <div class="cmc-check-dot {dot_cls}"></div>
            <span style="color:#F5F7FB;font-weight:500;">{html.escape(scanner_name)}</span>
            <span style="color:#718096;">&middot;</span>
            <span style="color:#A7B3C8;">{html.escape(status_text)}</span>
        </div>
        """
    st.markdown(f'<div class="cmc-card" style="padding:0.8rem 1.2rem;margin-bottom:1.2rem;">{status_items}</div>', unsafe_allow_html=True)

    # Findings section with filters
    st.markdown('<div class="cmc-section-label">Inspection Findings</div>', unsafe_allow_html=True)

    fc1, fc2, fc3 = st.columns([2, 2, 3])
    with fc1:
        sev_filter = st.multiselect(
            "Filter by Severity",
            ["Critical", "High", "Medium", "Low"],
            default=["Critical", "High", "Medium", "Low"],
            label_visibility="collapsed",
        )
    with fc2:
        all_cats = sorted({f["category"] for f in findings}) if findings else []
        cat_filter = st.multiselect(
            "Filter by Category",
            all_cats,
            default=all_cats,
            label_visibility="collapsed",
        )
    with fc3:
        search_q = st.text_input(
            "Search findings",
            placeholder="Search by file path, rule ID, or keyword...",
            label_visibility="collapsed",
        )

    filtered = [
        f for f in findings
        if f["severity"] in sev_filter
        and f["category"] in cat_filter
        and (
            not search_q
            or search_q.lower() in f.get("file_path", "").lower()
            or search_q.lower() in f.get("title", "").lower()
            or search_q.lower() in f.get("rule_id", "").lower()
        )
    ]

    st.markdown(
        f'<div style="font-size:0.8rem;color:#718096;margin:0.4rem 0 0.8rem 0;">'
        f'Displaying <strong style="color:#F5F7FB;">{len(filtered)}</strong> of {len(findings)} findings'
        f'</div>',
        unsafe_allow_html=True,
    )

    if not findings:
        st.markdown("""
        <div class="cmc-card" style="text-align:center;padding:2.5rem 1.5rem;">
            <div style="font-size:1.1rem;font-weight:700;color:#22D3EE;margin-bottom:0.3rem;">No Security Findings Detected</div>
            <div style="font-size:0.82rem;color:#A7B3C8;">
                All implemented static detection rules passed cleanly on this codebase.
            </div>
        </div>
        """, unsafe_allow_html=True)
    elif not filtered:
        st.info("No findings match the current severity or category filters.")
    else:
        for idx, f in enumerate(filtered):
            sev = f.get("severity", "Low")
            badge_cls = {
                "Critical": "sev-critical",
                "High": "sev-high",
                "Medium": "sev-medium",
            }.get(sev, "sev-low")

            line_s = f":{f['line_number']}" if f.get("line_number") is not None else ""
            file_loc = f"{f.get('file_path', 'unknown')}{line_s}"

            # Safely escape all text so raw HTML tags or script injection won't break layout
            safe_title = html.escape(str(f.get("title", "")))
            safe_rule = html.escape(str(f.get("rule_id", "")))
            safe_cat = html.escape(str(f.get("category", "")))
            safe_expl = html.escape(str(f.get("explanation", "")))
            safe_impact = html.escape(str(f.get("impact", "Potential security exposure")))
            safe_fix = html.escape(str(f.get("remediation", "")))
            safe_loc = html.escape(file_loc)

            with st.expander(f"{sev.upper()} — {f.get('title', '')}  |  {file_loc}", expanded=(idx == 0)):
                st.markdown(f"""
                <div class="cmc-finding-header">
                    <span class="cmc-badge {badge_cls}">{sev}</span>
                    <span class="cmc-rule-pill">{safe_rule}</span>
                    <span class="cmc-cat-label">{safe_cat}</span>
                </div>
                <div class="cmc-finding-body">
                    <strong>Explanation:</strong> {safe_expl}<br>
                    <strong>Why It Matters:</strong> {safe_impact}<br>
                    <strong>Recommended Fix:</strong> <span class="cmc-finding-fix">{safe_fix}</span>
                </div>
                <div class="cmc-finding-loc">Location: {safe_loc}</div>
                """, unsafe_allow_html=True)

                snippet = f.get("snippet", "")
                if snippet:
                    st.code(snippet, language="text")

    # Reports section
    st.markdown('<div style="height: 1.5rem;"></div>', unsafe_allow_html=True)
    st.markdown('<div class="cmc-section-label">Export Audit Reports</div>', unsafe_allow_html=True)

    report_dict = generate_audit_report_dict(profile, findings, score_data, statuses)
    json_payload = export_json_report(report_dict)
    html_payload = export_html_report(report_dict)

    st.markdown(
        '<div style="font-size:0.82rem;color:#A7B3C8;margin-bottom:1rem;">'
        "Download self-contained audit artifacts for compliance records, security reviews, or pull request attachments."
        "</div>",
        unsafe_allow_html=True,
    )

    d1, d2 = st.columns(2, gap="large")
    with d1:
        st.markdown("""
        <div class="cmc-card" style="height:100%;">
            <div style="font-weight:600;font-size:0.92rem;color:#F5F7FB;margin-bottom:0.2rem;">📄 HTML Compliance Report</div>
            <div style="font-size:0.78rem;color:#718096;margin-bottom:0.9rem;">
                Standalone, self-contained HTML file. Opens in any browser with zero external network dependencies.
            </div>
        </div>
        """, unsafe_allow_html=True)
        st.download_button(
            "Download HTML Report",
            data=html_payload,
            file_name=f"checkmycode_audit_{profile['project_name']}.html",
            mime="text/html",
            type="primary",
            use_container_width=True,
        )

    with d2:
        st.markdown("""
        <div class="cmc-card" style="height:100%;">
            <div style="font-weight:600;font-size:0.92rem;color:#F5F7FB;margin-bottom:0.2rem;">📋 JSON Machine-Readable Report</div>
            <div style="font-size:0.78rem;color:#718096;margin-bottom:0.9rem;">
                Standardized structured JSON payload for CI/CD gates, defect trackers, or automated tooling.
            </div>
        </div>
        """, unsafe_allow_html=True)
        st.download_button(
            "Download JSON Report",
            data=json_payload,
            file_name=f"checkmycode_audit_{profile['project_name']}.json",
            mime="application/json",
            use_container_width=True,
        )

    with st.expander("🔍 Optional: Inspect Raw Structured JSON", expanded=False):
        st.json(report_dict)

    # Post-Scan Functional Feedback Form
    render_feedback_section(profile["project_name"])


# ---------------------------------------------------------------------------
# COMPONENT: POST-SCAN FEEDBACK FORM
# ---------------------------------------------------------------------------
def render_feedback_section(project_name: str):
    st.markdown("""
    <div class="cmc-feedback-box">
        <div style="font-weight:700;font-size:1.05rem;color:#F5F7FB;margin-bottom:0.2rem;">Help us improve CheckMyCode</div>
        <div style="font-size:0.8rem;color:#A7B3C8;margin-bottom:1rem;">
            Was this scan useful? Tell us what worked and what we can improve.
        </div>
    </div>
    """, unsafe_allow_html=True)

    if st.session_state.get("feedback_submitted", False):
        st.success("✅ Thank you! Your feedback has been recorded and saved successfully.")
        return

    fb_c1, fb_c2 = st.columns(2)
    with fb_c1:
        exp = st.selectbox(
            "1. Overall experience",
            ["Excellent", "Good", "Average", "Poor"],
            index=0,
            key="fb_exp",
        )
        useful = st.selectbox(
            "2. Were the results useful?",
            ["Yes", "Partly", "No"],
            index=0,
            key="fb_useful",
        )
    with fb_c2:
        role = st.selectbox(
            "3. What best describes you?",
            ["Developer", "Student", "Freelancer", "Other"],
            index=0,
            key="fb_role",
        )
        email = st.text_input(
            "4. Email address (Optional)",
            placeholder="you@domain.com (only if you want a response)",
            key="fb_email",
        )

    improve_text = st.text_area(
        "5. What should we improve? (Optional)",
        placeholder="Tell us what checks were most helpful, what rules were noisy, or what features you would like next...",
        key="fb_improve",
        height=90,
    )

    if st.button("Submit Feedback", type="primary"):
        # Validation
        if email.strip():
            # Basic email format validation
            if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email.strip()):
                st.error("Please enter a valid email address or leave the field blank.")
                return

        payload = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "project_name": project_name,
            "overall_experience": exp,
            "results_useful": useful,
            "user_role": role,
            "email": email.strip() if email.strip() else None,
            "improvement_notes": improve_text.strip(),
        }

        if _save_feedback(payload):
            st.session_state["feedback_submitted"] = True
            st.rerun()
        else:
            st.error("An error occurred while saving feedback. Please try again.")


# ---------------------------------------------------------------------------
# VIEW: TERMS & CONDITIONS PAGE
# ---------------------------------------------------------------------------
def render_terms_page():
    st.markdown("""
    <div style="margin-bottom: 1.5rem;">
        <div style="font-size: 1.4rem; font-weight: 800; color: #F5F7FB;">Terms & Conditions</div>
        <div style="font-size: 0.8rem; color: #718096;">Effective Date: October 2026</div>
    </div>

    <div class="cmc-legal-box">
        <h2>1. Acceptance of Terms</h2>
        <p>By accessing or using the CheckMyCode platform ("Service"), you agree to be bound by these Terms and Conditions. If you disagree with any part of these terms, you may not access or use the Service.</p>

        <h2>2. Purpose and Scope of CheckMyCode</h2>
        <p>CheckMyCode provides developer-focused, automated, rule-based static security checks and deployment-readiness assessments for source code archives. The Service is provided for informational and developmental review purposes.</p>

        <h2>3. User Responsibility for Uploaded Projects</h2>
        <p>You retain full ownership of all source code, manifests, and files you upload to CheckMyCode. You are solely responsible for the content of your submitted archives and ensure they do not violate any applicable local or international laws.</p>

        <h2>4. Authorization to Scan Submitted Code</h2>
        <p>You warrant that you own or have obtained all necessary licenses, permissions, and authorizations from rightsholders to upload, analyze, and scan any code or archives submitted to the Service.</p>

        <h2>5. Acceptable Use</h2>
        <p>You agree not to use CheckMyCode to:</p>
        <ul>
            <li>Upload malicious archives intentionally crafted to attack or disrupt the scanning infrastructure (such as zip bombs or path-traversal exploits).</li>
            <li>Attempt to reverse-engineer, decompile, or bypass the application's boundaries or sandbox protections.</li>
            <li>Scan proprietary code belonging to third parties without their documented authorization.</li>
        </ul>

        <h2>6. Limitations of Automated Security Scanning</h2>
        <p>CheckMyCode utilizes static pattern recognition, regular expression rules, and curated vulnerability advisory databases. It does not execute your code or observe dynamic runtime behaviors. Automated scanning has inherent limitations and can produce both false positives and false negatives.</p>

        <h2>7. No Guarantee of Complete Vulnerability Detection</h2>
        <p>CheckMyCode makes no guarantee, warranty, or representation that it will identify every security vulnerability, bug, configuration defect, or compliance issue. A clean scan score indicates solely that no issues matched the implemented rule sets.</p>

        <h2>8. User Responsibility Prior to Deployment</h2>
        <p>You are exclusively responsible for independently reviewing and validating all scan findings, code changes, and configuration modifications before promoting any software to testing or production deployment environments.</p>

        <h2>9. Service Availability & Potential Errors</h2>
        <p>The Service is provided on an "as is" and "as available" basis. We do not warrant that the application will be uninterrupted, error-free, or compatible with every possible project archive layout.</p>

        <h2>10. Limitation of Liability</h2>
        <p>To the maximum extent permitted by applicable law, CheckMyCode, its developers, and contributors shall not be liable for any indirect, incidental, special, consequential, or punitive damages, including loss of data, security breaches, system outages, or production failures arising out of or in connection with the use of the Service.</p>

        <h2>11. Modifications to Terms</h2>
        <p>We reserve the right to revise or update these Terms and Conditions at any time. Continued use of the platform after changes constitutes acceptance of the amended terms.</p>

        <h2>12. Contact & Notices</h2>
        <p>For questions or comments regarding these Terms and Conditions, please utilize the feedback form located within the application.</p>
    </div>
    """, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# VIEW: PRIVACY POLICY PAGE
# ---------------------------------------------------------------------------
def render_privacy_page():
    st.markdown("""
    <div style="margin-bottom: 1.5rem;">
        <div style="font-size: 1.4rem; font-weight: 800; color: #F5F7FB;">Privacy Policy</div>
        <div style="font-size: 0.8rem; color: #718096;">Effective Date: October 2026</div>
    </div>

    <div class="cmc-legal-box">
        <h2>1. Information You Submit</h2>
        <p>When you use CheckMyCode, you provide project archive files (ZIP format) containing source code, dependency specifications (such as requirements.txt or package.json), and deployment configurations (such as Dockerfile or docker-compose.yml).</p>

        <h2>2. How Uploaded Files Are Processed</h2>
        <p>Uploaded archives are processed as follows:</p>
        <ul>
            <li>Archives are uncompressed strictly inside an isolated, temporary system directory with safe path validation (rejecting zip-slip traversal attempts).</li>
            <li>Static analyzers inspect file contents purely through read operations without running compilers, interpreters, or executing code.</li>
            <li>When you click "New Scan" or the application session terminates, temporary directories and unpacked files are purged from the filesystem.</li>
        </ul>

        <h2>3. Data Storage & Retention Policies</h2>
        <p><strong>Code Archives:</strong> CheckMyCode does not permanently store your submitted source code or project archives in a persistent database. Files exist only in volatile temporary directories during active analysis.</p>
        <p><strong>Scan Results:</strong> Scan findings and readiness scores exist within your browser's active session state. If you refresh or close the tab without downloading an HTML/JSON report, the results are released from memory.</p>

        <h2>4. No External AI API Transmission</h2>
        <p>CheckMyCode operates offline with respect to code inspection. Your source code, manifests, and tokens are <strong>never</strong> transmitted to third-party artificial intelligence services, external LLM APIs, or commercial data brokers.</p>

        <h2>5. Vulnerability Advisory Database Inquiries</h2>
        <p>Dependency CVE checks rely entirely on an internal, bundled database of known vulnerability advisories maintained within the application codebase. No outbound network requests are made during dependency scanning.</p>

        <h2>6. Secret Masking & Protection</h2>
        <p>When secret tokens (such as AWS keys or API credentials) are detected, CheckMyCode automatically masks the sensitive characters in findings summaries, browser displays, and exported compliance reports to prevent credential leakage.</p>

        <h2>7. Feedback Form Information</h2>
        <p>If you choose to submit the optional post-scan feedback form, we collect your ratings, feedback comments, and optional email address. Feedback is stored locally in an application JSON log. We do not attach your source code or project files to feedback submissions.</p>

        <h2>8. Cookies & Analytics</h2>
        <p>CheckMyCode does not use third-party tracking cookies, advertising pixels, or invasive telemetry. Streamlit framework session tokens are maintained solely for application navigation and state management.</p>

        <h2>9. User Rights & Contact</h2>
        <p>Because project archives are deleted automatically following analysis and no user accounts are required, we do not maintain persistent profiles. For feedback or questions regarding data handling, please submit a message via the in-app feedback form.</p>
    </div>
    """, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# MAIN APPLICATION ROUTER
# ---------------------------------------------------------------------------
def main():
    render_header()

    current_page = st.session_state.get("current_page", "home")

    if current_page == "home":
        render_homepage()
    elif current_page == "scan":
        render_scan_page()
    elif current_page == "results":
        render_results_page()
    elif current_page == "terms":
        render_terms_page()
    elif current_page == "privacy":
        render_privacy_page()
    else:
        render_homepage()

    render_footer()


if __name__ == "__main__":
    main()

