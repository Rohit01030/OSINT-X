"""
Phase 5 unit verification tests.
Tests IP Intelligence Module service functions, consent gate enforcement, consent logging, and API endpoints.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from database.session import Base, get_db
from models.finding import Finding
from models.consent_log import ConsentLog
from services import ip_service
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


def override_get_db_p5():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


def test_ip_service_units():
    # 1. Test GeoIP function structure
    geoip_res = ip_service.get_geoip_data("8.8.8.8")
    assert "ip" in geoip_res
    assert geoip_res["ip"] == "8.8.8.8"

    # 2. Test Reputation check structure
    rep_res = ip_service.get_ip_reputation("127.0.0.1")
    assert rep_res["is_loopback"] is True
    assert rep_res["is_bogon"] is True


def test_ip_analyze_and_consent_gate_api_workflow():
    app.dependency_overrides[get_db] = override_get_db_p5
    client = TestClient(app)

    # 1. Register user
    reg_resp = client.post(
        "/api/auth/register",
        json={"username": "ipanalyst", "email": "ip@example.com", "password": "SecurePassword123!"},
    )
    assert reg_resp.status_code == 201

    # 2. Login
    login_resp = client.post(
        "/api/auth/login",
        json={"username_or_email": "ipanalyst", "password": "SecurePassword123!"},
    )
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 3. Create Investigation Case
    case_resp = client.post(
        "/api/investigations",
        json={"title": "IP Recon Case", "description": "Testing Phase 5 IP scan", "tags": ["ip_test"]},
        headers=headers,
    )
    assert case_resp.status_code == 201
    inv_id = case_resp.json()["id"]

    # 4. Passive IP Analyze (consent_confirmed=False)
    passive_resp = client.post(
        "/api/ip/analyze",
        json={"investigation_id": inv_id, "target": "8.8.8.8", "consent_confirmed": False},
        headers=headers,
    )
    assert passive_resp.status_code == 200
    p_data = passive_resp.json()
    assert p_data["target"] == "8.8.8.8"
    assert p_data["consent_confirmed"] is False
    assert len(p_data["open_ports"]) == 0

    # 5. Port scan endpoint WITHOUT consent (expects 403 Forbidden)
    forbidden_resp = client.post(
        "/api/ip/scan-ports",
        json={"investigation_id": inv_id, "target": "127.0.0.1", "consent_confirmed": False},
        headers=headers,
    )
    assert forbidden_resp.status_code == 403

    # 6. Active Port Scan WITH Consent Gate confirmed
    active_resp = client.post(
        "/api/ip/scan-ports",
        json={"investigation_id": inv_id, "target": "127.0.0.1", "consent_confirmed": True},
        headers=headers,
    )
    assert active_resp.status_code == 200
    a_data = active_resp.json()
    assert a_data["consent_confirmed"] is True
    assert a_data["consent_logged"] is True

    # 7. Verify finding and consent log in database
    db = TestingSessionLocal()
    finding_obj = db.query(Finding).filter(Finding.id == a_data["finding_id"]).first()
    assert finding_obj is not None
    assert finding_obj.module == "ip"
    assert finding_obj.investigation_id == inv_id

    consent_obj = db.query(ConsentLog).filter(ConsentLog.investigation_id == inv_id).first()
    assert consent_obj is not None
    assert consent_obj.target == "127.0.0.1"
    db.close()
