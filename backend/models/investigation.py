"""
Investigation database model.
"""
import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Text, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from database.session import Base


class Investigation(Base):
    __tablename__ = "investigations"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=True)
    status = Column(String(20), nullable=False, default="active", index=True)  # active, archived, closed
    tags = Column(JSON, default=list, nullable=False)  # e.g., ["phishing", "domain_check"]
    created_by = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    creator = relationship("User", backref="investigations")
    findings = relationship("Finding", back_populates="investigation", cascade="all, delete-orphan")
    consent_logs = relationship("ConsentLog", back_populates="investigation", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Investigation title={self.title} status={self.status}>"
