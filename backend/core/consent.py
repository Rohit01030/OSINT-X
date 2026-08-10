"""
Consent gate verification and logger.
Enforces authorized-target confirmation before active OSINT scans (Phase 5).
"""
import logging
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from models.consent_log import ConsentLog

logger = logging.getLogger(__name__)


def log_consent(
    db: Session,
    investigation_id: str,
    target: str,
    user_id: str = None,
    client_ip: str = None,
) -> ConsentLog:
    """
    Records explicit user confirmation of target scanning authorization in consent_logs.
    """
    consent_record = ConsentLog(
        user_id=user_id,
        investigation_id=investigation_id,
        target=target,
        confirmed_at=datetime.now(timezone.utc),
        ip_address=client_ip,
    )
    db.add(consent_record)
    db.commit()
    db.refresh(consent_record)
    logger.info(
        "Consent logged for target='%s' investigation='%s' user='%s'",
        target,
        investigation_id,
        user_id,
    )
    return consent_record
