"""
Reports API Router.

Endpoints for generating and retrieving JSON, CSV, and HTML/PDF intelligence reports.
"""
from fastapi import APIRouter, Depends, HTTPException, Response, status
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database.session import get_db
from api.deps import get_current_user
from models.user import User
from models.report import Report
from services import report_service

router = APIRouter(prefix="/reports", tags=["Report Generator Module"])


class GenerateReportRequest(BaseModel):
    investigation_id: str
    format: str = "json"  # 'json', 'csv', 'pdf'


@router.post("/generate")
def generate_report(
    req: GenerateReportRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Generates intelligence report in requested format (JSON, CSV, PDF/HTML)."""
    fmt = req.format.lower()

    if fmt == "json":
        data = report_service.generate_json_report(db, req.investigation_id)
        if "error" in data:
            raise HTTPException(status_code=404, detail=data["error"])
        report_record = report_service.save_report_record(db, req.investigation_id, "json", "Structured JSON Export")
        return {"report_id": report_record.id, "format": "json", "report_data": data}

    elif fmt == "csv":
        csv_data = report_service.generate_csv_report(db, req.investigation_id)
        if csv_data.startswith("Error:"):
            raise HTTPException(status_code=404, detail=csv_data)
        report_record = report_service.save_report_record(db, req.investigation_id, "csv", "Tabular CSV Export")
        return Response(
            content=csv_data,
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=report_{req.investigation_id[:8]}.csv"}
        )

    elif fmt in ["pdf", "html"]:
        html_data = report_service.generate_html_pdf_report(db, req.investigation_id)
        if "Error:" in html_data:
            raise HTTPException(status_code=404, detail="Investigation not found")
        report_record = report_service.save_report_record(db, req.investigation_id, "pdf", "Executive PDF Briefing")
        return HTMLResponse(content=html_data)

    else:
        raise HTTPException(status_code=400, detail="Invalid report format. Choose json, csv, or pdf.")


@router.get("/investigation/{investigation_id}")
def list_investigation_reports(
    investigation_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Lists all previously generated reports for an investigation."""
    reports = db.query(Report).filter(Report.investigation_id == investigation_id).all()
    return [
        {
            "id": r.id,
            "investigation_id": r.investigation_id,
            "report_type": r.report_type,
            "report_path": r.report_path,
            "content_summary": r.content_summary,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in reports
    ]


@router.get("/download/{report_id}")
def download_report(
    report_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieves generated report metadata by ID."""
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    return {
        "id": report.id,
        "investigation_id": report.investigation_id,
        "report_type": report.report_type,
        "report_path": report.report_path,
        "content_summary": report.content_summary,
        "created_at": report.created_at.isoformat() if report.created_at else None,
    }
