"""Administrator-protected, read-only AI evidence API."""
from datetime import datetime
from typing import Literal
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app.api.security import verify_admin_key
from app.services.ai_analysis_service import list_ai_analysis, summarize_ai_analysis

router = APIRouter(prefix="/ai", tags=["ai-analysis"], dependencies=[Depends(verify_admin_key)])


class AIAnalysisItem(BaseModel):
    event_id: UUID
    model_version: str
    status: Literal["processed", "failed", "skipped"]
    anomaly_score: float | None
    latency_ms: float | None
    processed_at: datetime | None
    hostname: str
    source: str
    event_type: str


@router.get("/analysis", response_model=list[AIAnalysisItem])
def get_ai_analysis(limit: int = Query(default=20, ge=1, le=50)):
    """Expose stored scores, never raw logs, alerts, risk decisions or errors."""
    try:
        return list_ai_analysis(limit=limit)
    except (psycopg.Error, OSError, KeyError):
        # Do not reveal database configuration or stored event content.
        raise HTTPException(status_code=503, detail="AI analysis storage unavailable") from None


class AIAnalysisSummary(BaseModel):
    model_version: str
    total: int
    processed: int
    failed: int
    skipped: int
    average_latency_ms: float | None
    last_processed_at: datetime | None


@router.get("/summary", response_model=AIAnalysisSummary)
def get_ai_summary():
    """Administrator-only aggregate statistics, not security risk verdicts."""
    try:
        return summarize_ai_analysis()
    except (psycopg.Error, OSError, KeyError):
        raise HTTPException(status_code=503, detail="AI analysis storage unavailable") from None
