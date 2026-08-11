"""
Local AI Engine API Router.

Endpoints for investigation summaries, risk score explanations, cross-investigation
IOC correlation, MITRE ATT&CK matrix mapping, and natural language search.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from typing import Optional
from sqlalchemy.orm import Session

from database.session import get_db
from api.deps import get_current_user
from models.user import User
from services import ai_service
from services.ollama_client import ollama_client
from core.config import settings

router = APIRouter(prefix="/ai", tags=["Local AI Engine"])


class InvestigationRequest(BaseModel):
    investigation_id: str


class NLSearchRequest(BaseModel):
    query: str


@router.get("/health")
def get_ai_health(current_user: User = Depends(get_current_user)):
    """Returns status of local Ollama server and AI configuration."""
    available = ollama_client.is_available()
    return {
        "status": "online" if available else "fallback_mode",
        "ollama_base_url": settings.OLLAMA_BASE_URL,
        "ollama_model": settings.OLLAMA_MODEL,
        "api_key_required": False,
        "local_execution": True,
        "available": available,
    }


@router.post("/summarize")
def summarize_investigation(
    req: InvestigationRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Generates an executive narrative summary for an investigation using local AI."""
    res = ai_service.generate_investigation_summary(db, req.investigation_id)
    if "error" in res:
        raise HTTPException(status_code=404, detail=res["error"])
    return res


@router.post("/risk-explain")
def explain_risk_score(
    req: InvestigationRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Calculates deterministic risk score and provides AI breakdown explanation."""
    res = ai_service.calculate_and_explain_risk(db, req.investigation_id)
    if "error" in res:
        raise HTTPException(status_code=404, detail=res["error"])
    return res


@router.post("/correlate-iocs")
def correlate_investigation_iocs(
    req: InvestigationRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Cross-correlates investigation IOCs against all other cases in the database."""
    res = ai_service.correlate_iocs(db, req.investigation_id)
    if "error" in res:
        raise HTTPException(status_code=404, detail=res["error"])
    return res


@router.get("/attack-mapping/{investigation_id}")
def get_mitre_attack_mapping(
    investigation_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Returns mapped MITRE ATT&CK Matrix techniques for investigation findings."""
    res = ai_service.map_mitre_attack(db, investigation_id)
    if "error" in res:
        raise HTTPException(status_code=404, detail=res["error"])
    return res


@router.post("/nl-search")
def natural_language_search(
    req: NLSearchRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Translates free-text natural language query into structured database filters."""
    if not req.query.strip():
        raise HTTPException(status_code=400, detail="Search query cannot be empty")
    return ai_service.natural_language_search(db, req.query)
