"""
Local AI Engine API Router.

Endpoints for investigation summaries, risk score explanations, cross-investigation
IOC correlation, MITRE ATT&CK matrix mapping, natural language search, and interactive AI chat.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from typing import Optional, List
from sqlalchemy.orm import Session

from database.session import get_db
from api.deps import get_current_user
from models.user import User
from models.investigation import Investigation
from models.finding import Finding
from services import ai_service
from services.ollama_client import ollama_client
from core.config import settings

router = APIRouter(prefix="/ai", tags=["Local AI Engine"])


class InvestigationRequest(BaseModel):
    investigation_id: str


class NLSearchRequest(BaseModel):
    query: str


class ChatRequest(BaseModel):
    message: str
    investigation_id: Optional[str] = None
    history: Optional[list] = None  # List of {"role": "user"|"assistant", "content": str}


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


@router.post("/chat")
def ai_chat(
    req: ChatRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Interactive AI chat endpoint. Accepts a free-form user message and optional
    investigation context (investigation_id) to anchor responses to live case data.
    Returns the AI-generated assistant reply.
    """
    if not req.message.strip():
        raise HTTPException(status_code=400, detail="Message cannot be empty")

    # Build context section from investigation if provided
    context_section = ""
    if req.investigation_id:
        inv = db.query(Investigation).filter(Investigation.id == req.investigation_id).first()
        if inv:
            findings = db.query(Finding).filter(Finding.investigation_id == req.investigation_id).all()
            finding_lines = "\n".join(
                f"  - [{f.module.upper()}] {f.type}" for f in findings
            ) or "  - No findings yet."
            context_section = (
                f"\n\n[ACTIVE INVESTIGATION CONTEXT]\n"
                f"Title: {inv.title}\n"
                f"Status: {inv.status}\n"
                f"Tags: {', '.join(inv.tags or []) or 'none'}\n"
                f"Findings ({len(findings)} total):\n{finding_lines}"
            )

    # Build conversation history prefix
    history_text = ""
    if req.history:
        for turn in req.history[-6:]:  # Last 6 turns to avoid context overflow
            role = "User" if turn.get("role") == "user" else "Assistant"
            history_text += f"{role}: {turn.get('content', '')}\n"

    full_prompt = (
        f"{history_text}"
        f"User: {req.message.strip()}{context_section}\n\n"
        "Assistant:"
    )

    system_prompt = (
        "You are OSINT-X AI, an expert Open-Source Intelligence (OSINT) security analyst assistant. "
        "You help analysts investigate threats, understand findings, interpret intelligence data, and "
        "suggest next investigation steps. Be concise, technically precise, and always reference "
        "the investigation context when provided. Never invent or fabricate intelligence findings."
    )

    result = ollama_client.generate(full_prompt, system_prompt=system_prompt)

    return {
        "reply": result.get("response", "").strip(),
        "model_used": result.get("model", settings.OLLAMA_MODEL),
        "offline_fallback": result.get("offline_fallback", False),
        "investigation_id": req.investigation_id,
    }
