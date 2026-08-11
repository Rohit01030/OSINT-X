"""
Audit Logging Service for OSINT-X.

Provides audit trail persistence, paginated query retrieval, and security event stats.
"""
import logging
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from models.audit_log import AuditLog

logger = logging.getLogger(__name__)


def log_action(
    db: Session,
    user_id: Optional[str],
    action: str,
    target: Optional[str] = None,
    ip_address: Optional[str] = None
) -> AuditLog:
    """Logs a security-sensitive action into the audit_logs database table."""
    audit_entry = AuditLog(
        user_id=user_id or "anonymous",
        action=action.upper(),
        target=target,
        ip_address=ip_address or "127.0.0.1"
    )
    db.add(audit_entry)
    db.commit()
    db.refresh(audit_entry)
    return audit_entry


def get_audit_logs(
    db: Session,
    skip: int = 0,
    limit: int = 50,
    action_filter: Optional[str] = None
) -> Dict[str, Any]:
    """Retrieves paginated audit log trails."""
    query = db.query(AuditLog)

    if action_filter:
        query = query.filter(AuditLog.action == action_filter.upper())

    total = query.count()
    logs = query.order_by(AuditLog.timestamp.desc()).offset(skip).limit(limit).all()

    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "logs": [
            {
                "id": log.id,
                "user_id": log.user_id,
                "action": log.action,
                "target": log.target,
                "ip_address": log.ip_address,
                "timestamp": log.timestamp.isoformat() if log.timestamp else None,
            }
            for log in logs
        ]
    }


def get_audit_stats(db: Session) -> Dict[str, Any]:
    """Calculates audit action distribution statistics."""
    total = db.query(AuditLog).count()
    logs = db.query(AuditLog).all()

    action_counts = {}
    for log in logs:
        action_counts[log.action] = action_counts.get(log.action, 0) + 1

    return {
        "total_audit_records": total,
        "action_breakdown": action_counts
    }
