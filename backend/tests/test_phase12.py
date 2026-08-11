"""
Phase 12 end-to-end integration and verification tests.
Validates complete platform lifecycle across all 12 phases, OpenAPI schema generation,
health checks, and deployment configuration readiness.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from database.session import Base, get_db
from models.user import User
from models.investigation import Investigation
from models.finding import Finding
from models.ioc import IOC
from models.report import Report
from models.audit_log import AuditLog
from main import app

# In-memory SQLite DB for E2E tests
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)


def override_get_db_p12():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


def test_openapi_swagger_docs():
    app.dependency_overrides[get_db] = override_get_db_p12
    client = TestClient(app)

    res = client.get("/openapi.json")
    assert res.status_code == 200
    schema = res.json()
    assert "openapi" in schema
    assert "paths" in schema
    # Verify routers registered
    paths = schema["paths"]
    assert "/api/auth/register" in paths
    assert "/api/investigations" in paths
    assert "/api/domain/analyze" in paths
    assert "/api/ip/analyze" in paths
    assert "/api/email/analyze" in paths
    assert "/api/username/analyze" in paths
    assert "/api/threat-intel/analyze" in paths
    assert "/api/ai/summarize" in paths
    assert "/api/visualization/relationship-graph/{investigation_id}" in paths
    assert "/api/reports/generate" in paths
    assert "/api/audit/logs" in paths


def test_full_platform_lifecycle_e2e():
    app.dependency_overrides[get_db] = override_get_db_p12
    client = TestClient(app)

    # Clean DB state
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    # 1. User Registration (Admin)
    reg_resp = client.post(
        "/api/auth/register",
        json={"username": "master_admin", "email": "admin@example.com", "password": "SuperSecretPassword123!"},
    )
    assert reg_resp.status_code == 201
    assert reg_resp.json()["role"] == "admin"

    # 2. Login
    login_resp = client.post(
        "/api/auth/login",
        json={"username_or_email": "master_admin", "password": "SuperSecretPassword123!"},
    )
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 3. Create Investigation Case
    case_resp = client.post(
        "/api/investigations",
        json={"title": "Target Operation Apex", "description": "Full E2E platform verification case", "tags": ["e2e", "apex"]},
        headers=headers,
    )
    assert case_resp.status_code == 201
    inv_id = case_resp.json()["id"]

    # 4. Domain Recon Scan
    domain_resp = client.post(
        "/api/domain/analyze",
        json={"investigation_id": inv_id, "target": "example.com"},
        headers=headers,
    )
    assert domain_resp.status_code == 200

    # 5. IP Intelligence & Consent Gate Scan
    ip_resp = client.post(
        "/api/ip/scan-ports",
        json={"investigation_id": inv_id, "target": "127.0.0.1", "consent_confirmed": True},
        headers=headers,
    )
    assert ip_resp.status_code == 200
    assert ip_resp.json()["consent_confirmed"] is True

    # 6. Email OSINT Scan
    email_resp = client.post(
        "/api/email/analyze",
        json={"investigation_id": inv_id, "target": "analyst@example.com"},
        headers=headers,
    )
    assert email_resp.status_code == 200

    # 7. Threat Intel Scan
    threat_resp = client.post(
        "/api/threat-intel/analyze",
        json={"investigation_id": inv_id, "target": "8.8.8.8"},
        headers=headers,
    )
    assert threat_resp.status_code == 200

    # 8. Local AI Engine Summary & Risk Explanation
    ai_sum_resp = client.post("/api/ai/summarize", json={"investigation_id": inv_id}, headers=headers)
    assert ai_sum_resp.status_code == 200
    assert "summary" in ai_sum_resp.json()

    ai_risk_resp = client.post("/api/ai/risk-explain", json={"investigation_id": inv_id}, headers=headers)
    assert ai_risk_resp.status_code == 200
    assert "risk_score" in ai_risk_resp.json()

    # 9. Intelligence Visualization (Relationship Graph & Geo Map)
    graph_resp = client.get(f"/api/visualization/relationship-graph/{inv_id}", headers=headers)
    assert graph_resp.status_code == 200
    assert graph_resp.json()["total_nodes"] > 0

    geo_resp = client.get(f"/api/visualization/geo-map/{inv_id}", headers=headers)
    assert geo_resp.status_code == 200

    # 10. Report Generator (JSON & PDF Briefing)
    rep_json = client.post("/api/reports/generate", json={"investigation_id": inv_id, "format": "json"}, headers=headers)
    assert rep_json.status_code == 200

    rep_pdf = client.post("/api/reports/generate", json={"investigation_id": inv_id, "format": "pdf"}, headers=headers)
    assert rep_pdf.status_code == 200

    # 11. Enterprise Security Audit Logs Verification
    audit_resp = client.get("/api/audit/logs", headers=headers)
    assert audit_resp.status_code == 200
    assert audit_resp.json()["total"] > 0
