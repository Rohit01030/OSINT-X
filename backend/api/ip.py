"""
IP Intelligence API Router.
Provides endpoints for GeoIP lookups, ASN & ISP analysis, IP reputation,
and consent-gated active port scanning.
"""
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database.session import get_db
from models.user import User
from models.investigation import Investigation
from services import ip_service
from api.deps import get_current_user
from core.rate_limit import limiter

router = APIRouter(prefix="/ip", tags=["ip"])


class IPAnalyzeRequest(BaseModel):
    investigation_id: str = Field(..., description="ID of the investigation case to attach findings to")
    target: str = Field(..., description="IP target to analyze, e.g. 8.8.8.8")
    consent_confirmed: bool = Field(False, description="Explicit user confirmation for active port scanning")


class IPPortScanRequest(BaseModel):
    investigation_id: str = Field(..., description="ID of the investigation case")
    target: str = Field(..., description="Target IP address")
    consent_confirmed: bool = Field(True, description="Explicit authorization confirmation")
    custom_ports: Optional[List[int]] = Field(None, description="Optional custom list of ports to scan")


@router.post("/analyze", response_model=Dict[str, Any], status_code=status.HTTP_200_OK)
@limiter.limit("20/minute")
def analyze_ip(
    request: Request,
    payload: IPAnalyzeRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Executes IP Intelligence scan (GeoIP, ASN, IP reputation).
    If consent_confirmed=True, active port scanning is also executed and logged to consent_logs.
    """
    # Verify investigation case access
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
        client_ip = request.client.host if request.client else None
        results = ip_service.analyze_ip(
            db=db,
            investigation_id=payload.investigation_id,
            raw_target=payload.target,
            consent_confirmed=payload.consent_confirmed,
            user_id=current_user.id,
            client_ip=client_ip,
        )
        return results
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"IP analysis failed: {str(e)}")


@router.post("/scan-ports", response_model=Dict[str, Any], status_code=status.HTTP_200_OK)
@limiter.limit("10/minute")
def scan_ports(
    request: Request,
    payload: IPPortScanRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Executes consent-gated active port scan on target IP.
    Enforces authorization confirmation and logs audit entry to consent_logs.
    """
    if not payload.consent_confirmed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Target scanning authorization consent is required before performing active port scans.",
        )

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

    client_ip = request.client.host if request.client else None
    results = ip_service.analyze_ip(
        db=db,
        investigation_id=payload.investigation_id,
        raw_target=payload.target,
        consent_confirmed=True,
        user_id=current_user.id,
        client_ip=client_ip,
    )
    return results


@router.get("/geoip")
@limiter.limit("30/minute")
def get_ip_geoip(request: Request, ip: str = Query(..., description="Target IP address")):
    """Performs GeoIP and ASN/ISP lookup for target IP."""
    return ip_service.get_geoip_data(ip)


@router.get("/reputation")
@limiter.limit("30/minute")
def get_ip_reputation(request: Request, ip: str = Query(..., description="Target IP address")):
    """Evaluates IP reputation and threat score."""
    return ip_service.get_ip_reputation(ip)
