"""
Visualization API Router.

Endpoints for network relationship graphs, chronological event timelines,
geographic intelligence maps, and Chart.js metrics.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from database.session import get_db
from api.deps import get_current_user
from models.user import User
from services import visualization_service

router = APIRouter(prefix="/visualization", tags=["Visualization Module"])


@router.get("/relationship-graph/{investigation_id}")
def get_relationship_graph_data(
    investigation_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Returns network relationship graph nodes and edges for an investigation."""
    res = visualization_service.get_relationship_graph(db, investigation_id)
    if "error" in res:
        raise HTTPException(status_code=404, detail=res["error"])
    return res


@router.get("/timeline/{investigation_id}")
def get_timeline_data(
    investigation_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Returns chronological investigation activity timeline events."""
    res = visualization_service.get_timeline(db, investigation_id)
    if "error" in res:
        raise HTTPException(status_code=404, detail=res["error"])
    return res


@router.get("/geo-map/{investigation_id}")
def get_geo_map_data(
    investigation_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Returns GeoIP location coordinates for map rendering."""
    res = visualization_service.get_geo_map(db, investigation_id)
    if "error" in res:
        raise HTTPException(status_code=404, detail=res["error"])
    return res


@router.get("/metrics/{investigation_id}")
def get_chart_metrics_data(
    investigation_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Returns module distribution, severity ratings, and IOC metrics for Chart.js."""
    res = visualization_service.get_chart_metrics(db, investigation_id)
    if "error" in res:
        raise HTTPException(status_code=404, detail=res["error"])
    return res
