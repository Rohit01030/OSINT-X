"""
Service layer for investigation case management and dashboard metrics calculation.
"""
from typing import Optional, List, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import func, or_

from models.investigation import Investigation
from models.finding import Finding
from schemas.investigation import InvestigationCreate, InvestigationUpdate


def create_investigation(db: Session, user_id: str, obj_in: InvestigationCreate) -> Investigation:
    """Creates a new investigation case assigned to the given user."""
    db_obj = Investigation(
        title=obj_in.title,
        description=obj_in.description,
        tags=obj_in.tags or [],
        status="active",
        created_by=user_id,
    )
    db.add(db_obj)
    db.commit()
    db.refresh(db_obj)
    return db_obj


def get_investigation_by_id(db: Session, investigation_id: str) -> Optional[Investigation]:
    """Retrieves an investigation by ID."""
    return db.query(Investigation).filter(Investigation.id == investigation_id).first()


def list_investigations(
    db: Session,
    user_id: Optional[str] = None,
    status: Optional[str] = None,
    tag: Optional[str] = None,
    search: Optional[str] = None,
    skip: int = 0,
    limit: int = 20,
) -> Tuple[List[Investigation], int]:
    """
    Lists investigations matching optional filters (status, tag, search query) with pagination.
    Returns (investigations_list, total_count).
    """
    query = db.query(Investigation)

    if user_id:
        query = query.filter(Investigation.created_by == user_id)

    if status:
        query = query.filter(Investigation.status == status)

    if search:
        search_fmt = f"%{search}%"
        query = query.filter(
            or_(
                Investigation.title.ilike(search_fmt),
                Investigation.description.ilike(search_fmt),
            )
        )

    # Filtering JSON tags (for SQLite / PostgreSQL compatibility, checking tag in string or python filter)
    total_count = query.count()
    investigations = query.order_by(Investigation.created_at.desc()).offset(skip).limit(limit).all()

    if tag:
        # In-memory filter for tag matching
        tag_lower = tag.lower()
        investigations = [inv for inv in investigations if any(tag_lower in (t.lower() for t in (inv.tags or [])) for _ in [1])]
        total_count = len(investigations)

    return investigations, total_count


def update_investigation(
    db: Session, db_obj: Investigation, obj_in: InvestigationUpdate
) -> Investigation:
    """Updates fields of an existing investigation case."""
    update_data = obj_in.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        if value is not None:
            setattr(db_obj, field, value)

    db.add(db_obj)
    db.commit()
    db.refresh(db_obj)
    return db_obj


def delete_investigation(db: Session, db_obj: Investigation) -> bool:
    """Deletes an investigation case."""
    db.delete(db_obj)
    db.commit()
    return True


def get_dashboard_stats(db: Session, user_id: Optional[str] = None) -> dict:
    """
    Computes dashboard metrics: case counts by status, total findings count, and recent cases.
    """
    query = db.query(Investigation)
    if user_id:
        query = query.filter(Investigation.created_by == user_id)

    total_investigations = query.count()
    active_count = query.filter(Investigation.status == "active").count()
    archived_count = query.filter(Investigation.status == "archived").count()
    closed_count = query.filter(Investigation.status == "closed").count()

    # Total findings count
    findings_query = db.query(func.count(Finding.id))
    if user_id:
        findings_query = findings_query.join(Investigation).filter(Investigation.created_by == user_id)
    total_findings = findings_query.scalar() or 0

    # Recent 5 investigations
    recent_investigations = query.order_by(Investigation.created_at.desc()).limit(5).all()

    return {
        "total_investigations": total_investigations,
        "active_count": active_count,
        "archived_count": archived_count,
        "closed_count": closed_count,
        "total_findings": total_findings,
        "recent_investigations": recent_investigations,
    }
