"""
Phase 11 unit verification tests.
Tests Security Headers Middleware, AuditLog table persistence, Cache Manager fallback mode,
API pagination, and FastAPI audit router.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from database.session import Base, get_db
from models.audit_log import AuditLog
from core.cache import cache
from services import audit_service
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


def override_get_db_p11():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


def test_security_headers_middleware():
    app.dependency_overrides[get_db] = override_get_db_p11
    client = TestClient(app)

    res = client.get("/")
    assert res.status_code == 200
    assert res.headers.get("X-Frame-Options") == "DENY"
    assert res.headers.get("X-Content-Type-Options") == "nosniff"
    assert res.headers.get("X-XSS-Protection") == "1; mode=block"
    assert "Strict-Transport-Security" in res.headers


def test_cache_manager_fallback():
    # Verify set and get with fallback
    assert cache.set("test_key", {"status": "ok"}, expire_seconds=60) is True
    val = cache.get("test_key")
    assert val == {"status": "ok"}
    assert cache.delete("test_key") is True
    assert cache.get("test_key") is None


def test_audit_log_service_units():
    db = TestingSessionLocal()
    log_entry = audit_service.log_action(db, "user-123", "ANALYZE_DOMAIN", "example.com", "192.168.1.100")
    assert log_entry.id is not None
    assert log_entry.action == "ANALYZE_DOMAIN"
    assert log_entry.target == "example.com"

    res = audit_service.get_audit_logs(db, skip=0, limit=10)
    assert res["total"] >= 1
    assert len(res["logs"]) >= 1

    stats = audit_service.get_audit_stats(db)
    assert stats["total_audit_records"] >= 1
    assert stats["action_breakdown"].get("ANALYZE_DOMAIN", 0) >= 1
    db.close()


def test_audit_api_workflow():
    app.dependency_overrides[get_db] = override_get_db_p11
    client = TestClient(app)

    # 1. Reset DB tables
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    # 2. Register User
    reg_resp = client.post(
        "/api/auth/register",
        json={"username": "audit_analyst", "email": "auditor@example.com", "password": "SecurePassword123!"},
    )
    assert reg_resp.status_code == 201

    # 3. Login
    login_resp = client.post(
        "/api/auth/login",
        json={"username_or_email": "audit_analyst", "password": "SecurePassword123!"},
    )
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 4. Access Audit Logs API
    logs_resp = client.get("/api/audit/logs?skip=0&limit=10", headers=headers)
    assert logs_resp.status_code == 200
    l_data = logs_resp.json()
    assert "total" in l_data
    assert "logs" in l_data

    # 5. Access Audit Stats API
    stats_resp = client.get("/api/audit/stats", headers=headers)
    assert stats_resp.status_code == 200
    assert "total_audit_records" in stats_resp.json()
