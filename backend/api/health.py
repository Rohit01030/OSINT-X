"""
Health and version endpoints.

Used by Docker healthchecks, uptime monitoring, and to confirm database connectivity.
"""
from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session
from database.session import get_db

router = APIRouter(tags=["system"])

APP_VERSION = "0.1.0"


@router.get("/health")
def health_check(db: Session = Depends(get_db)):
    db_status = "disconnected"
    try:
        db.execute(text("SELECT 1"))
        db_status = "connected"
    except Exception as e:
        db_status = f"error: {str(e)}"

    return {
        "status": "ok" if db_status == "connected" else "degraded",
        "database": db_status,
        "version": APP_VERSION,
    }


@router.get("/version")
def version():
    return {"version": APP_VERSION}
