"""FastAPI Application for CheckMyCode."""

from __future__ import annotations

import io
import os
import json
import logging
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, Form, HTTPException, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response

from backend.app.schemas.models import (
    FeedbackRequest,
    FeedbackResponse,
    HealthResponse,
    ScanResponseModel,
)
from backend.app.services.scanner_service import (
    execute_scan,
    generate_reports_for_scan,
    get_scan,
)

logger = logging.getLogger("CheckMyCodeAPI")
FEEDBACK_FILE = Path(__file__).resolve().parent.parent.parent / "feedback_submissions.json"

app = FastAPI(
    title="CheckMyCode API",
    description="Developer-focused project security & readiness scanning platform",
    version="1.1.0",
)

# CORS configuration - support localhost dev + configurable production frontend origin
allowed_origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:3001",
    "http://127.0.0.1:3001",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
]

frontend_origin_env = os.getenv("FRONTEND_URL", "").strip()
if frontend_origin_env:
    for origin in frontend_origin_env.split(","):
        cleaned = origin.strip().rstrip("/")
        if cleaned and cleaned not in allowed_origins:
            allowed_origins.append(cleaned)

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$|^https://.*\.vercel\.app$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health", response_model=HealthResponse)
def health_check():
    return {
        "status": "healthy",
        "service": "CheckMyCode API",
        "version": "1.1.0",
    }


@app.post("/api/scans", response_model=ScanResponseModel)
async def create_scan(
    file: UploadFile = File(...),
    secrets: bool = Form(True),
    code_sec: bool = Form(True),
    deps: bool = Form(True),
    config: bool = Form(True),
):
    if not file.filename.lower().endswith(".zip"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only ZIP archives (.zip) are supported.",
        )

    content = await file.read()
    if len(content) > 50 * 1024 * 1024:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File size exceeds the 50 MB maximum allowed limit.",
        )

    project_name = file.filename.rsplit(".", 1)[0]
    prefs = {
        "secrets": secrets,
        "code_sec": code_sec,
        "deps": deps,
        "config": config,
    }

    try:
        scan_result = execute_scan(io.BytesIO(content), project_name, prefs)
        return scan_result
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        logger.error(f"Scan failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during project security analysis.",
        )


@app.get("/api/scans/{scan_id}", response_model=ScanResponseModel)
def get_scan_result(scan_id: str):
    scan_data = get_scan(scan_id)
    if not scan_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan ID '{scan_id}' not found.",
        )
    return scan_data


def _sanitize_filename(name: str) -> str:
    """Sanitize project name for safe, clean Content-Disposition filenames."""
    import re
    cleaned = re.sub(r"[^\w\.-]", "_", name).strip("._")
    if not cleaned:
        cleaned = "Project"
    return cleaned[:50]


@app.get("/api/scans/{scan_id}/report")
def download_scan_report(scan_id: str, format: str = "pdf"):
    try:
        reports = generate_reports_for_scan(scan_id)
    except Exception as e:
        logger.error(f"Error compiling report for scan {scan_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate the requested scan report.",
        )

    if not reports:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan ID '{scan_id}' not found.",
        )

    scan_record = get_scan(scan_id)
    raw_proj_name = scan_record["project_name"] if scan_record else "Project"
    clean_proj_name = _sanitize_filename(raw_proj_name)

    fmt = format.lower().strip()
    if fmt == "pdf":
        pdf_bytes = reports.get("pdf")
        if not pdf_bytes:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="PDF report generation failed.",
            )
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="CheckMyCode_{clean_proj_name}_Report.pdf"',
                "Content-Length": str(len(pdf_bytes)),
            },
        )
    elif fmt == "json":
        return JSONResponse(
            content=json.loads(reports["json"]),
            headers={
                "Content-Disposition": f'attachment; filename="CheckMyCode_{clean_proj_name}_Report.json"'
            },
        )
    else:
        return HTMLResponse(
            content=reports["html"],
            headers={
                "Content-Disposition": f'attachment; filename="CheckMyCode_{clean_proj_name}_Report.html"'
            },
        )


@app.post("/api/feedback", response_model=FeedbackResponse)
def submit_feedback(feedback: FeedbackRequest):
    try:
        submissions = []
        if FEEDBACK_FILE.exists():
            try:
                submissions = json.loads(FEEDBACK_FILE.read_text(encoding="utf-8"))
                if not isinstance(submissions, list):
                    submissions = []
            except Exception:
                submissions = []

        submissions.append(feedback.model_dump())
        FEEDBACK_FILE.write_text(json.dumps(submissions, indent=2), encoding="utf-8")
        return {"success": True, "message": "Feedback submitted successfully."}
    except Exception as e:
        logger.error(f"Feedback persistence failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to save feedback submission.",
        )

