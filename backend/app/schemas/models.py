"""Pydantic data models for CheckMyCode API."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class FindingModel(BaseModel):
    id: str
    rule_id: str
    category: str
    severity: str
    title: str
    file_path: str
    line_number: Optional[int] = None
    explanation: str
    impact: str
    remediation: str
    snippet: Optional[str] = None


class ProjectProfileModel(BaseModel):
    project_name: str
    total_files: int
    inspected_files: int
    approx_loc: int
    languages: List[str]
    frameworks: List[str]
    manifests: List[str]
    configs: List[str]


class ReadinessScoreModel(BaseModel):
    score: float
    status: str
    badge_color: str
    badge_bg: str
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    methodology: str


class ScanResponseModel(BaseModel):
    scan_id: str
    project_name: str
    profile: ProjectProfileModel
    score_data: ReadinessScoreModel
    findings: List[FindingModel]
    check_statuses: Dict[str, str]


class FeedbackRequest(BaseModel):
    project_name: str
    overall_experience: str
    results_useful: str
    user_role: str
    email: Optional[str] = None
    improvement_notes: Optional[str] = None


class FeedbackResponse(BaseModel):
    success: bool
    message: str


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str

