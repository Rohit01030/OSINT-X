"""
Phase 4 unit verification tests.
Tests Domain Intelligence Module service functions and API endpoints.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from database.session import Base, get_db
from models.finding import Finding
from services import domain_service
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


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)


def test_domain_service_units():
    # 1. Test DNS lookup function structure
    dns_res = domain_service.get_dns_records("example.com")
    assert "A" in dns_res
    assert "MX" in dns_res
    assert "NS" in dns_res
    assert "TXT" in dns_res

    # 2. Test SSL cert inspector structure
    ssl_res = domain_service.get_ssl_certificate("example.com")
    assert "valid" in ssl_res
    assert "subject" in ssl_res
    assert "issuer" in ssl_res

    # 3. Test HTTP security headers function structure
    headers_res = domain_service.get_http_headers_and_tech("example.com")
    assert "security_headers" in headers_res
    assert "security_score" in headers_res
    assert "tech_stack" in headers_res


def test_domain_analyze_api_workflow():
    # 1. Register user
    reg_resp = client.post(
        "/api/auth/register",
        json={"username": "domainanalyst", "email": "domain@example.com", "password": "SecurePassword123!"},
    )
    assert reg_resp.status_code == 201

    # 2. Login
    login_resp = client.post(
        "/api/auth/login",
        json={"username_or_email": "domainanalyst", "password": "SecurePassword123!"},
    )
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 3. Create Investigation Case
    case_resp = client.post(
        "/api/investigations",
        json={"title": "Domain Recon Case", "description": "Testing Phase 4 domain scan", "tags": ["domain_test"]},
        headers=headers,
    )
    assert case_resp.status_code == 201
    inv_id = case_resp.json()["id"]

    # 4. Execute Domain Analyze API
    analyze_resp = client.post(
        "/api/domain/analyze",
        json={"investigation_id": inv_id, "target": "example.com"},
        headers=headers,
    )
    assert analyze_resp.status_code == 200
    data = analyze_resp.json()
    assert data["target"] == "example.com"
    assert "whois" in data
    assert "dns" in data
    assert "ssl" in data
    assert "http" in data
    assert "subdomains" in data
    assert "finding_id" in data

    # 5. Verify finding written to database
    db = TestingSessionLocal()
    finding_obj = db.query(Finding).filter(Finding.id == data["finding_id"]).first()
    assert finding_obj is not None
    assert finding_obj.module == "domain"
    assert finding_obj.type == "domain_scan"
    assert finding_obj.investigation_id == inv_id
    db.close()
