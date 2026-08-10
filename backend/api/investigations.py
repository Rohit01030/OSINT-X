"""
Investigation Case Management API router.
Provides CRUD endpoints for managing OSINT investigation cases and fetching dashboard summary metrics.
"""
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from database.session import get_db
from models.user import User
from schemas.investigation import (
    InvestigationCreate,
    InvestigationUpdate,
    InvestigationResponse,
    DashboardSummaryResponse,
)
from services import investigation_service
from api.deps import get_current_user

router = APIRouter(prefix="/investigations", tags=["investigations"])


@router.post("", response_model=InvestigationResponse, status_code=status.HTTP_201_CREATED)
def create_investigation(
    investigation_in: InvestigationCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Creates a new investigation case.
    """
    db_obj = investigation_service.create_investigation(db, current_user.id, investigation_in)
    return db_obj


@router.get("", response_model=List[InvestigationResponse])
def list_investigations(
    status: Optional[str] = Query(None, description="Filter by status (active, archived, closed)"),
    tag: Optional[str] = Query(None, description="Filter by tag"),
    search: Optional[str] = Query(None, description="Search across title and description"),
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Lists investigation cases matching search and filter criteria with pagination.
    """
    investigations, _ = investigation_service.list_investigations(
        db,
        user_id=current_user.id if current_user.role != "admin" else None,
        status=status,
        tag=tag,
        search=search,
        skip=skip,
        limit=limit,
    )
    
    # Calculate findings_count for response
    results = []
    for inv in investigations:
        resp = InvestigationResponse.model_validate(inv)
        resp.findings_count = len(inv.findings) if inv.findings else 0
        results.append(resp)

    return results


@router.get("/dashboard", response_model=DashboardSummaryResponse)
def get_dashboard_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Returns aggregated dashboard metrics including case status counts and recent cases.
    """
    user_id = current_user.id if current_user.role != "admin" else None
    stats = investigation_service.get_dashboard_stats(db, user_id=user_id)

    # Format recent_investigations with findings_count
    formatted_recent = []
    for inv in stats["recent_investigations"]:
        resp = InvestigationResponse.model_validate(inv)
        resp.findings_count = len(inv.findings) if inv.findings else 0
        formatted_recent.append(resp)

    return {
        "total_investigations": stats["total_investigations"],
        "active_count": stats["active_count"],
        "archived_count": stats["archived_count"],
        "closed_count": stats["closed_count"],
        "total_findings": stats["total_findings"],
        "recent_investigations": formatted_recent,
    }


@router.get("/{investigation_id}", response_model=InvestigationResponse)
def get_investigation(
    investigation_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieves a single investigation case by ID.
    """
    inv = investigation_service.get_investigation_by_id(db, investigation_id)
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found",
        )

    # Check access permission if analyst
    if current_user.role != "admin" and inv.created_by != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this investigation",
        )

    resp = InvestigationResponse.model_validate(inv)
    resp.findings_count = len(inv.findings) if inv.findings else 0
    return resp


@router.put("/{investigation_id}", response_model=InvestigationResponse)
def update_investigation(
    investigation_id: str,
    investigation_in: InvestigationUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Updates an investigation case details or status.
    """
    inv = investigation_service.get_investigation_by_id(db, investigation_id)
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found",
        )

    if current_user.role != "admin" and inv.created_by != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to modify this investigation",
        )

    updated_inv = investigation_service.update_investigation(db, inv, investigation_in)
    resp = InvestigationResponse.model_validate(updated_inv)
    resp.findings_count = len(updated_inv.findings) if updated_inv.findings else 0
    return resp


@router.delete("/{investigation_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_investigation(
    investigation_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Deletes an investigation case.
    """
    inv = investigation_service.get_investigation_by_id(db, investigation_id)
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found",
        )

    if current_user.role != "admin" and inv.created_by != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to delete this investigation",
        )

    investigation_service.delete_investigation(db, inv)
    return None
