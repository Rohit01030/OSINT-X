"""
Pydantic schemas for investigation case management and dashboard metrics.
"""
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field, ConfigDict


class InvestigationBase(BaseModel):
    title: str = Field(..., min_length=1, max_length=255, examples=["Operation PhishHunter"])
    description: Optional[str] = Field(None, examples=["Investigation into suspicious phishing domain."])
    tags: List[str] = Field(default_factory=list, examples=[["phishing", "domain_check"]])


class InvestigationCreate(InvestigationBase):
    pass


class InvestigationUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    status: Optional[str] = Field(None, pattern="^(active|archived|closed)$")
    tags: Optional[List[str]] = None


class InvestigationResponse(InvestigationBase):
    id: str
    status: str
    created_by: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    findings_count: int = 0

    model_config = ConfigDict(from_attributes=True)


class DashboardSummaryResponse(BaseModel):
    total_investigations: int
    active_count: int
    archived_count: int
    closed_count: int
    total_findings: int
    recent_investigations: List[InvestigationResponse]
