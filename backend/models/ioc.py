"""
Indicator of Compromise (IOC) database model.
Used for correlation matching across multiple investigations.
"""
import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Float
from database.session import Base


class IOC(Base):
    __tablename__ = "iocs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    value = Column(String(500), nullable=False, index=True)
    type = Column(String(50), nullable=False, index=True)  # ip, domain, hash, email
    first_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    last_seen = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    source = Column(String(100), nullable=True)  # module name or threat intel feed
    reputation_score = Column(Float, default=0.0, nullable=False)  # 0.0 (safe) to 10.0 (high risk)

    def __repr__(self):
        return f"<IOC value={self.value} type={self.type} score={self.reputation_score}>"
