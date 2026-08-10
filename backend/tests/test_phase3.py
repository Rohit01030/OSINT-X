"""
Phase 3 unit verification tests.
Tests investigation CRUD operations, search/filtering, and dashboard summary endpoints.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from database.session import Base, get_db
from main import app

# In-memory SQLite DB with StaticPool for test session isolation
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


@pytest.fixture
def auth_headers():
    """Helper fixture to register a test user and return Authorization headers."""
    register_payload = {
        "username": "caseanalyst",
        "email": "caseanalyst@example.com",
        "password": "SecurePassword123!",
    }
    client.post("/api/auth/register", json=register_payload)

    login_resp = client.post(
        "/api/auth/login",
        json={"username_or_email": "caseanalyst", "password": "SecurePassword123!"},
    )
    token = login_resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_investigation_crud_and_dashboard(auth_headers):
    # 1. Create Investigation Case
    create_payload = {
        "title": "Phishing Domain Investigation",
        "description": "Investigating suspicious domain phishing-example.com",
        "tags": ["phishing", "domain_check"],
    }
    create_resp = client.post("/api/investigations", json=create_payload, headers=auth_headers)
    assert create_resp.status_code == 201
    created_data = create_resp.json()
    assert created_data["title"] == "Phishing Domain Investigation"
    assert created_data["status"] == "active"
    assert "phishing" in created_data["tags"]
    inv_id = created_data["id"]

    # 2. Get Investigation by ID
    get_resp = client.get(f"/api/investigations/{inv_id}", headers=auth_headers)
    assert get_resp.status_code == 200
    assert get_resp.json()["id"] == inv_id

    # 3. List Investigations
    list_resp = client.get("/api/investigations", headers=auth_headers)
    assert list_resp.status_code == 200
    assert len(list_resp.json()) == 1

    # 4. List Investigations with Search & Filter
    search_resp = client.get("/api/investigations?search=Phishing", headers=auth_headers)
    assert len(search_resp.json()) == 1

    tag_resp = client.get("/api/investigations?tag=domain_check", headers=auth_headers)
    assert len(tag_resp.json()) == 1

    # 5. Update Investigation
    update_payload = {"status": "archived", "tags": ["phishing", "archived_case"]}
    update_resp = client.put(f"/api/investigations/{inv_id}", json=update_payload, headers=auth_headers)
    assert update_resp.status_code == 200
    assert update_resp.json()["status"] == "archived"
    assert "archived_case" in update_resp.json()["tags"]

    # 6. Dashboard Metrics Summary
    dash_resp = client.get("/api/investigations/dashboard", headers=auth_headers)
    assert dash_resp.status_code == 200
    dash_data = dash_resp.json()
    assert dash_data["total_investigations"] == 1
    assert dash_data["archived_count"] == 1

    # 7. Delete Investigation
    del_resp = client.delete(f"/api/investigations/{inv_id}", headers=auth_headers)
    assert del_resp.status_code == 204

    # Verify deletion
    get_del_resp = client.get(f"/api/investigations/{inv_id}", headers=auth_headers)
    assert get_del_resp.status_code == 404
