"""
Consent log database model.
Audits user authorization confirmation before active scans (e.g. port scans).
"""
import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from database.session import Base


class ConsentLog(Base):
    __tablename__ = "consent_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    investigation_id = Column(String(36), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True)
    target = Column(String(255), nullable=False)  # target IP or domain scanned
    confirmed_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    ip_address = Column(String(45), nullable=True)  # client IP making request

    # Relationships
    user = relationship("User", backref="consent_logs")
    investigation = relationship("Investigation", back_populates="consent_logs")

    def __repr__(self):
        return f"<ConsentLog target={self.target} user_id={self.user_id} confirmed_at={self.confirmed_at}>"
