"""
Audit Trail API Router.

Endpoints for reviewing enterprise security audit logs, activity pagination, and audit metrics.
"""
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session
from typing import Optional

from database.session import get_db
from api.deps import get_current_user
from models.user import User
from services import audit_service

router = APIRouter(prefix="/audit", tags=["Audit Logs Module"])


@router.get("/logs")
def get_paginated_audit_logs(
    skip: int = Query(0, ge=0, description="Pagination offset"),
    limit: int = Query(50, ge=1, le=200, description="Pagination limit"),
    action: Optional[str] = Query(None, description="Optional action filter"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieves paginated enterprise security audit logs."""
    # Log access to audit logs
    audit_service.log_action(db, current_user.id, "VIEW_AUDIT_LOGS", "audit_logs")
    return audit_service.get_audit_logs(db, skip=skip, limit=limit, action_filter=action)


@router.get("/stats")
def get_audit_statistics(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Returns security audit distribution statistics."""
    return audit_service.get_audit_stats(db)
