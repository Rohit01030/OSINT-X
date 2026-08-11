"""
Phase 7 unit verification tests.
Tests Threat Intelligence services, unified risk scoring, database persistence, and API router.
"""
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from database.session import Base, get_db
from models.finding import Finding
from models.ioc import IOC
from services import threat_intel_service
from core.config import settings
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


def override_get_db_p7():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


def test_threat_intel_simulation_mode():
    # 1. Test clean target simulation
    vt_clean = threat_intel_service.check_virustotal("clean-domain.com", "domain")
    assert vt_clean["data"]["attributes"]["last_analysis_stats"]["malicious"] == 0
    assert vt_clean["data"]["attributes"]["reputation"] == 100

    # 2. Test malicious target simulation
    vt_mal = threat_intel_service.check_virustotal("malicious.com", "domain")
    assert vt_mal["data"]["attributes"]["last_analysis_stats"]["malicious"] == 15
    assert vt_mal["data"]["attributes"]["reputation"] == -50

    # 3. Test AbuseIPDB IP simulation
    abuse_clean = threat_intel_service.check_abuseipdb("8.8.8.8")
    assert abuse_clean["data"]["abuseConfidenceScore"] == 0

    abuse_mal = threat_intel_service.check_abuseipdb("1.1.1.1")
    assert abuse_mal["data"]["abuseConfidenceScore"] == 85

    # 4. Test Shodan IP simulation
    shodan_res = threat_intel_service.check_shodan("1.1.1.1")
    assert 80 in shodan_res["ports"]
    assert shodan_res["isp"] == "Cloudflare, Inc."


@patch("httpx.Client.get")
def test_threat_intel_live_api_code_paths(mock_get):
    # Setup mock response
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"mock_response": "live_data"}
    mock_get.return_value = mock_resp

    # Temporarily set API keys to test live HTTP paths
    with patch.object(settings, "VIRUSTOTAL_API_KEY", "vt_test_key"):
        res = threat_intel_service.check_virustotal("google.com", "domain")
        assert res == {"mock_response": "live_data"}
        mock_get.assert_called_once_with(
            "https://www.virustotal.com/api/v3/domains/google.com",
            headers={"x-apikey": "vt_test_key"}
        )


def test_unified_reputation_scoring():
    db = TestingSessionLocal()
    
    # Analyze clean target
    clean_res = threat_intel_service.analyze_threat_intel(db, "fake-inv-id", "clean-domain.com")
    assert clean_res["reputation_score"] == 0.0

    # Analyze malicious target (VirusTotal detects 15 engines -> min(10.0, 15*2.0) = 10.0)
    mal_res = threat_intel_service.analyze_threat_intel(db, "fake-inv-id", "malicious.com")
    assert mal_res["reputation_score"] == 10.0

    # Verify IOC records updated in DB
    ioc_clean = db.query(IOC).filter(IOC.value == "clean-domain.com").first()
    assert ioc_clean is not None
    assert ioc_clean.reputation_score == 0.0

    ioc_mal = db.query(IOC).filter(IOC.value == "malicious.com").first()
    assert ioc_mal is not None
    assert ioc_mal.reputation_score == 10.0

    db.close()


def test_threat_intel_api_workflow():
    app.dependency_overrides[get_db] = override_get_db_p7
    client = TestClient(app)

    # 1. Register User
    reg_resp = client.post(
        "/api/auth/register",
        json={"username": "threat_hunter", "email": "hunter@example.com", "password": "SecurePassword123!"},
    )
    assert reg_resp.status_code == 201

    # 2. Login
    login_resp = client.post(
        "/api/auth/login",
        json={"username_or_email": "threat_hunter", "password": "SecurePassword123!"},
    )
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 3. Create Case
    case_resp = client.post(
        "/api/investigations",
        json={"title": "Threat Case", "description": "Testing Phase 7 endpoints", "tags": ["threat"]},
        headers=headers,
    )
    assert case_resp.status_code == 201
    inv_id = case_resp.json()["id"]

    # 4. Test Scan Endpoint (IP)
    scan_resp = client.post(
        "/api/threat-intel/analyze",
        json={"investigation_id": inv_id, "target": "1.1.1.1"},
        headers=headers,
    )
    assert scan_resp.status_code == 200
    s_data = scan_resp.json()
    assert s_data["target"] == "1.1.1.1"
    assert s_data["target_type"] == "ip"
    assert s_data["virustotal"] is not None
    assert s_data["abuseipdb"] is not None
    assert s_data["shodan"] is not None
    assert s_data["reputation_score"] > 5.0  # mock malicious 1.1.1.1 yields high score

    # 5. Check direct GET endpoints
    vt_resp = client.get("/api/threat-intel/virustotal?target=google.com&target_type=domain", headers=headers)
    assert vt_resp.status_code == 200
    assert "data" in vt_resp.json()

    abuse_resp = client.get("/api/threat-intel/abuseipdb?ip_address=8.8.8.8", headers=headers)
    assert abuse_resp.status_code == 200
    assert "data" in abuse_resp.json()

    shodan_resp = client.get("/api/threat-intel/shodan?ip_address=8.8.8.8", headers=headers)
    assert shodan_resp.status_code == 200
    assert "ip_str" in shodan_resp.json()
