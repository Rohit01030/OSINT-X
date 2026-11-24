# backend/api/phone.py
"""Phone OSINT FastAPI router.
Provides a POST endpoint to analyze a phone number.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Any, Dict

from services import phone_service

router = APIRouter(prefix="/api/phone", tags=["Phone OSINT"])


class PhoneRequest(BaseModel):
    investigation_id: int = Field(..., description="Parent investigation ID")
    phone_number: str = Field(..., description="Phone number (any format)")


@router.post("/analyze")
def analyze_phone(req: PhoneRequest) -> Dict[str, Any]:
    """Analyze a phone number and return enriched data.
    In a full implementation we'd store the result linked to the investigation.
    """
    result = phone_service.analyze_phone(req.phone_number)
    if not result.get("valid"):
        raise HTTPException(status_code=400, detail="Invalid phone number")
    return {"investigation_id": req.investigation_id, "phone": result}
