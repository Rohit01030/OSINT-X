"""
Phase 8 unit verification tests.
Tests Local AI Investigation Engine, Ollama client fallback mode, deterministic risk scoring,
MITRE ATT&CK lookup mapping, cross-investigation IOC correlation, NL search, and API router.
"""
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from database.session import Base, get_db
from models.investigation import Investigation
from models.finding import Finding
from models.ioc import IOC
from services.ollama_client import OllamaClient
from services import ai_service
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


def override_get_db_p8():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


def test_ollama_client_fallback_mode():
    client = OllamaClient(base_url="http://invalid-local-ollama:11434")
    # Should report offline / unavailable without crashing
    assert client.is_available() is False

    res = client.generate("Summarize findings for target example.com")
    assert res["status"] == "success"
    assert res["offline_fallback"] is True
    assert "Executive Summary" in res["response"]


def test_deterministic_risk_scoring_units():
    db = TestingSessionLocal()
    inv = Investigation(title="Risk Test Case", status="active")
    db.add(inv)
    db.commit()
    db.refresh(inv)

    # Add high-risk finding
    finding = Finding(
        investigation_id=inv.id,
        module="threat_intel",
        type="threat_intel_scan",
        data={
            "virustotal": {"data": {"attributes": {"last_analysis_stats": {"malicious": 8}}}},
            "abuseipdb": {"data": {"abuseConfidenceScore": 90}}
        }
    )
    db.add(finding)
    db.commit()

    res = ai_service.calculate_and_explain_risk(db, inv.id)
    assert res["risk_score"] > 5.0
    assert res["is_deterministic"] is True
    assert len(res["risk_factors"]) >= 2
    db.close()


def test_mitre_attack_mapping_units():
    db = TestingSessionLocal()
    inv = Investigation(title="MITRE Test Case", status="active")
    db.add(inv)
    db.commit()
    db.refresh(inv)

    finding = Finding(investigation_id=inv.id, module="domain", type="domain_scan", data={})
    db.add(finding)
    db.commit()

    res = ai_service.map_mitre_attack(db, inv.id)
    assert res["is_deterministic"] is True
    assert res["total_techniques_mapped"] >= 2
    tech_ids = [t["technique_id"] for t in res["mitre_attack_matrix"]]
    assert "T1590.002" in tech_ids
    db.close()


def test_cross_case_ioc_correlation_units():
    db = TestingSessionLocal()
    inv1 = Investigation(title="Case Alpha", status="active", tags=["phishing"])
    inv2 = Investigation(title="Case Beta", status="active", tags=["phishing"])
    db.add_all([inv1, inv2])
    db.commit()
    db.refresh(inv1)
    db.refresh(inv2)

    res = ai_service.correlate_iocs(db, inv1.id)
    assert res["current_investigation_id"] == inv1.id
    assert res["total_correlations_found"] == 1
    assert res["correlations"][0]["target_investigation_id"] == inv2.id
    db.close()


def test_natural_language_search_units():
    db = TestingSessionLocal()
    inv1 = Investigation(title="Phishing Site Recon", status="active")
    inv2 = Investigation(title="Ransomware Analysis", status="archived")
    db.add_all([inv1, inv2])
    db.commit()

    res = ai_service.natural_language_search(db, "active phishing cases")
    assert res["applied_filters"]["status"] == "active"
    assert res["total_matches"] == 1
    assert res["matches"][0]["title"] == "Phishing Site Recon"
    db.close()


def test_phase8_api_workflow():
    app.dependency_overrides[get_db] = override_get_db_p8
    client = TestClient(app)

    # 1. Register User
    reg_resp = client.post(
        "/api/auth/register",
        json={"username": "ai_analyst", "email": "ai@example.com", "password": "SecurePassword123!"},
    )
    assert reg_resp.status_code == 201

    # 2. Login
    login_resp = client.post(
        "/api/auth/login",
        json={"username_or_email": "ai_analyst", "password": "SecurePassword123!"},
    )
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 3. Check AI Health Endpoint
    health_resp = client.get("/api/ai/health", headers=headers)
    assert health_resp.status_code == 200
    h_data = health_resp.json()
    assert "api_key_required" in h_data
    assert h_data["api_key_required"] is False
    assert h_data["local_execution"] is True

    # 4. Create Investigation Case
    case_resp = client.post(
        "/api/investigations",
        json={"title": "AI Engine Case", "description": "Testing Phase 8 endpoints", "tags": ["ai_test"]},
        headers=headers,
    )
    assert case_resp.status_code == 201
    inv_id = case_resp.json()["id"]

    # 5. Test AI Summarize Endpoint
    sum_resp = client.post("/api/ai/summarize", json={"investigation_id": inv_id}, headers=headers)
    assert sum_resp.status_code == 200
    s_data = sum_resp.json()
    assert s_data["investigation_id"] == inv_id
    assert "summary" in s_data

    # 6. Test Risk Explanation Endpoint
    risk_resp = client.post("/api/ai/risk-explain", json={"investigation_id": inv_id}, headers=headers)
    assert risk_resp.status_code == 200
    r_data = risk_resp.json()
    assert "risk_score" in r_data
    assert "explanation" in r_data

    # 7. Test IOC Correlation Endpoint
    ioc_resp = client.post("/api/ai/correlate-iocs", json={"investigation_id": inv_id}, headers=headers)
    assert ioc_resp.status_code == 200
    assert "correlations" in ioc_resp.json()

    # 8. Test MITRE ATT&CK Mapping Endpoint
    mitre_resp = client.get(f"/api/ai/attack-mapping/{inv_id}", headers=headers)
    assert mitre_resp.status_code == 200
    m_data = mitre_resp.json()
    assert "mitre_attack_matrix" in m_data

    # 9. Test NL Search Endpoint
    nl_resp = client.post("/api/ai/nl-search", json={"query": "active AI cases"}, headers=headers)
    assert nl_resp.status_code == 200
    assert "matches" in nl_resp.json()
