"""
Email Intelligence API Router.
Provides endpoints for email security audits, Have I Been Pwned queries, and full email scanning.
"""
from typing import Dict, Any, List
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database.session import get_db
from models.user import User
from models.investigation import Investigation
from services import email_service
from api.deps import get_current_user
from core.rate_limit import limiter

router = APIRouter(prefix="/email", tags=["email"])


class EmailAnalyzeRequest(BaseModel):
    investigation_id: str = Field(..., description="ID of the investigation case to attach findings to")
    target: str = Field(..., description="Email address target to analyze, e.g. target@example.com")


@router.post("/analyze", response_model=Dict[str, Any], status_code=status.HTTP_200_OK)
@limiter.limit("20/minute")
def analyze_email(
    request: Request,
    payload: EmailAnalyzeRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Executes full Email Intelligence Scan (DNS security records check + Have I Been Pwned breach search)
    and saves results as a finding under the specified investigation case.
    """
    # Verify investigation case exists and check permission
    inv = db.query(Investigation).filter(Investigation.id == payload.investigation_id).first()
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation case not found",
        )

    if current_user.role != "admin" and inv.created_by != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this investigation case",
        )

    try:
        results = email_service.analyze_email(db, payload.investigation_id, payload.target)
        return results
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Email analysis failed: {str(e)}")


@router.get("/dns-security")
@limiter.limit("30/minute")
def get_email_dns_security(request: Request, email: str = Query(..., description="Target email address")):
    """Audits MX, SPF, DMARC, and DKIM settings for the target email's domain."""
    if "@" not in email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email target format",
        )
    return email_service.check_email_security(email)


@router.get("/breaches")
@limiter.limit("30/minute")
def get_email_breaches(request: Request, email: str = Query(..., description="Target email address")):
    """Checks breach status for an email address."""
    if "@" not in email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email target format",
        )
    return email_service.check_email_breaches(email)
