"""
Threat Intelligence API Router.
Provides endpoints for checking indicators against VirusTotal, AbuseIPDB, and Shodan APIs.
"""
from typing import Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database.session import get_db
from models.user import User
from models.investigation import Investigation
from services import threat_intel_service
from api.deps import get_current_user
from core.rate_limit import limiter

router = APIRouter(prefix="/threat-intel", tags=["threat_intel"])


class ThreatAnalyzeRequest(BaseModel):
    investigation_id: str = Field(..., description="ID of the investigation case to attach findings to")
    target: str = Field(..., description="IP, Domain, or Hash target to query")


@router.post("/analyze", response_model=Dict[str, Any], status_code=status.HTTP_200_OK)
@limiter.limit("20/minute")
def analyze_threat_intel(
    request: Request,
    payload: ThreatAnalyzeRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Executes full Threat Intelligence Lookup Scan (VirusTotal, AbuseIPDB, and Shodan)
    for the specified IP, Domain, or Hash, saving the results under the investigation.
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
        results = threat_intel_service.analyze_threat_intel(db, payload.investigation_id, payload.target)
        return results
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Threat intelligence scan failed: {str(e)}")


@router.get("/virustotal")
@limiter.limit("30/minute")
def check_virustotal(
    request: Request,
    target: str = Query(..., description="IP, Domain, or Hash target"),
    target_type: str = Query(..., description="Type of target: ip, domain, or hash")
):
    """Directly queries VirusTotal details for the target indicator."""
    if target_type not in ["ip", "domain", "hash"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid target_type. Must be 'ip', 'domain', or 'hash'.",
        )
    return threat_intel_service.check_virustotal(target, target_type)


@router.get("/abuseipdb")
@limiter.limit("30/minute")
def check_abuseipdb(
    request: Request,
    ip_address: str = Query(..., description="IP address to check")
):
    """Directly queries AbuseIPDB score for the IP address."""
    return threat_intel_service.check_abuseipdb(ip_address)


@router.get("/shodan")
@limiter.limit("30/minute")
def check_shodan(
    request: Request,
    ip_address: str = Query(..., description="IP address to check")
):
    """Directly queries Shodan details for the IP address."""
    return threat_intel_service.check_shodan(ip_address)
