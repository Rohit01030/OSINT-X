"""
Report model definition.

Tracks generated intelligence report files and metadata.
"""
import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship

from database.session import Base


class Report(Base):
    __tablename__ = "reports"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    investigation_id = Column(String, ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False)
    report_type = Column(String, nullable=False)  # 'json', 'csv', 'pdf'
    report_path = Column(String, nullable=True)
    content_summary = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    investigation = relationship("Investigation", backref="reports")
