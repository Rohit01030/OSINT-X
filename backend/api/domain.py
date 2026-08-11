"""
Domain Intelligence API Router.
Provides endpoints for domain analysis, WHOIS lookups, DNS resolution, SSL certificate inspection, and subdomain enumeration.
"""
from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database.session import get_db
from models.user import User
from models.investigation import Investigation
from services import domain_service
from api.deps import get_current_user
from core.rate_limit import limiter

router = APIRouter(prefix="/domain", tags=["domain"])


class DomainAnalyzeRequest(BaseModel):
    investigation_id: str = Field(..., description="ID of the investigation case to attach findings to")
    target: str = Field(..., description="Domain target to analyze, e.g. example.com")


@router.post("/analyze", response_model=Dict[str, Any], status_code=status.HTTP_200_OK)
@limiter.limit("20/minute")
def analyze_domain(
    request: Request,
    payload: DomainAnalyzeRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Executes full Domain Intelligence Scan (WHOIS/RDAP, DNS, SSL/TLS, Security Headers, Subdomain Enum)
    and saves results as a finding under the specified investigation case.
    """
    # Verify investigation case exists and permission
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
        results = domain_service.analyze_domain(db, payload.investigation_id, payload.target)
        return results
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Domain analysis failed: {str(e)}")


@router.get("/dns")
@limiter.limit("30/minute")
def get_domain_dns(request: Request, domain: str = Query(..., description="Target domain")):
    """Queries DNS records for a domain."""
    return domain_service.get_dns_records(domain)


@router.get("/whois")
@limiter.limit("30/minute")
def get_domain_whois(request: Request, domain: str = Query(..., description="Target domain")):
    """Queries WHOIS/RDAP data for a domain."""
    return domain_service.get_whois_data(domain)


@router.get("/ssl")
@limiter.limit("30/minute")
def get_domain_ssl(request: Request, domain: str = Query(..., description="Target domain")):
    """Audits SSL/TLS certificate for a domain."""
    return domain_service.get_ssl_certificate(domain)


@router.get("/headers")
@limiter.limit("30/minute")
def get_domain_headers(request: Request, domain: str = Query(..., description="Target domain")):
    """Inspects HTTP security headers and tech stack for a domain."""
    return domain_service.get_http_headers_and_tech(domain)


@router.get("/subdomains")
@limiter.limit("15/minute")
def get_domain_subdomains(request: Request, domain: str = Query(..., description="Target domain")):
    """Enumerates subdomains using Certificate Transparency logs."""
    return domain_service.get_subdomains(domain)
