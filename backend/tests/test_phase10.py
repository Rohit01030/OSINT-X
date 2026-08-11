"""
Phase 10 unit verification tests.
Tests Report Generator Module, JSON compilation, CSV formatting, HTML/PDF executive briefing rendering,
Report database model persistence, and FastAPI reports router.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from database.session import Base, get_db
from models.investigation import Investigation
from models.finding import Finding
from models.ioc import IOC
from models.report import Report
from services import report_service
from main import app

# In-memory SQLite DB for tests
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)


def override_get_db_p10():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


def test_json_report_generation_units():
    db = TestingSessionLocal()
    inv = Investigation(title="JSON Report Case", status="active", description="Testing Phase 10 report generator")
    db.add(inv)
    db.commit()
    db.refresh(inv)

    finding = Finding(investigation_id=inv.id, module="domain", type="domain_scan", data={"target": "example.com"})
    db.add(finding)
    db.commit()

    res = report_service.generate_json_report(db, inv.id)
    assert res["report_metadata"]["title"] == "JSON Report Case"
    assert "executive_summary" in res
    assert "risk_assessment" in res
    assert "findings" in res
    assert len(res["findings"]) == 1
    assert res["findings"][0]["module"] == "domain"
    db.close()


def test_csv_report_generation_units():
    db = TestingSessionLocal()
    inv = Investigation(title="CSV Report Case", status="active")
    db.add(inv)
    db.commit()
    db.refresh(inv)

    finding = Finding(investigation_id=inv.id, module="ip", type="ip_scan", data={"target": "8.8.8.8"})
    db.add(finding)
    db.commit()

    csv_data = report_service.generate_csv_report(db, inv.id)
    assert "=== OSINT-X INVESTIGATION REPORT ===" in csv_data
    assert "CSV Report Case" in csv_data
    assert "8.8.8.8" in csv_data
    db.close()


def test_html_pdf_report_rendering_units():
    db = TestingSessionLocal()
    inv = Investigation(title="HTML Briefing Case", status="active")
    db.add(inv)
    db.commit()
    db.refresh(inv)

    html_data = report_service.generate_html_pdf_report(db, inv.id)
    assert "<!DOCTYPE html>" in html_data
    assert "OSINT-X Intelligence Briefing" in html_data
    assert "HTML Briefing Case" in html_data
    db.close()


def test_report_database_model_units():
    db = TestingSessionLocal()
    inv = Investigation(title="Report Model Case", status="active")
    db.add(inv)
    db.commit()

    rec = report_service.save_report_record(db, inv.id, "pdf", "Test PDF Briefing")
    assert rec.id is not None
    assert rec.investigation_id == inv.id
    assert rec.report_type == "pdf"
    
    fetched = db.query(Report).filter(Report.id == rec.id).first()
    assert fetched is not None
    assert fetched.content_summary == "Test PDF Briefing"
    db.close()


def test_reports_api_workflow():
    app.dependency_overrides[get_db] = override_get_db_p10
    client = TestClient(app)

    # 1. Register User
    reg_resp = client.post(
        "/api/auth/register",
        json={"username": "report_analyst", "email": "reporter@example.com", "password": "SecurePassword123!"},
    )
    assert reg_resp.status_code == 201

    # 2. Login
    login_resp = client.post(
        "/api/auth/login",
        json={"username_or_email": "report_analyst", "password": "SecurePassword123!"},
    )
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 3. Create Case
    case_resp = client.post(
        "/api/investigations",
        json={"title": "Report API Case", "description": "Testing Phase 10 endpoints", "tags": ["report_test"]},
        headers=headers,
    )
    assert case_resp.status_code == 201
    inv_id = case_resp.json()["id"]

    # 4. Generate JSON Report API
    json_resp = client.post("/api/reports/generate", json={"investigation_id": inv_id, "format": "json"}, headers=headers)
    assert json_resp.status_code == 200
    j_data = json_resp.json()
    assert j_data["format"] == "json"
    assert "report_id" in j_data
    report_id = j_data["report_id"]

    # 5. Generate CSV Report API
    csv_resp = client.post("/api/reports/generate", json={"investigation_id": inv_id, "format": "csv"}, headers=headers)
    assert csv_resp.status_code == 200
    assert "text/csv" in csv_resp.headers["content-type"]

    # 6. Generate PDF/HTML Report API
    pdf_resp = client.post("/api/reports/generate", json={"investigation_id": inv_id, "format": "pdf"}, headers=headers)
    assert pdf_resp.status_code == 200
    assert "text/html" in pdf_resp.headers["content-type"]

    # 7. List Case Reports API
    list_resp = client.get(f"/api/reports/investigation/{inv_id}", headers=headers)
    assert list_resp.status_code == 200
    assert len(list_resp.json()) == 3  # json, csv, pdf reports logged

    # 8. Get Download Details API
    dl_resp = client.get(f"/api/reports/download/{report_id}", headers=headers)
    assert dl_resp.status_code == 200
    assert dl_resp.json()["id"] == report_id
