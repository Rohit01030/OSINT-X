"""
Phase 2 unit verification tests.
Tests password hashing, JWT encoding/decoding, registration, login, and auth dependencies.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from core.security import get_password_hash, verify_password, create_access_token, decode_access_token
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


def test_password_hashing():
    raw_password = "SecretPassword123!"
    hashed = get_password_hash(raw_password)

    assert hashed != raw_password
    assert verify_password(raw_password, hashed) is True
    assert verify_password("WrongPassword", hashed) is False


def test_jwt_token_creation_and_decoding():
    user_id = "test-user-uuid-123"
    token = create_access_token(subject=user_id, role="analyst")
    payload = decode_access_token(token)

    assert payload is not None
    assert payload.get("sub") == user_id
    assert payload.get("role") == "analyst"


def test_auth_api_workflow():
    # 1. Register first user (gets admin role)
    register_payload = {
        "username": "testadmin",
        "email": "admin@example.com",
        "password": "SecurePassword123!",
    }
    response = client.post("/api/auth/register", json=register_payload)
    assert response.status_code == 201
    data = response.json()
    assert data["username"] == "testadmin"
    assert data["email"] == "admin@example.com"
    assert data["role"] == "admin"

    # 2. Login with valid credentials
    login_payload = {
        "username_or_email": "testadmin",
        "password": "SecurePassword123!",
    }
    login_resp = client.post("/api/auth/login", json=login_payload)
    assert login_resp.status_code == 200
    token_data = login_resp.json()
    assert "access_token" in token_data
    token = token_data["access_token"]

    # 3. Access protected /api/auth/me endpoint
    headers = {"Authorization": f"Bearer {token}"}
    me_resp = client.get("/api/auth/me", headers=headers)
    assert me_resp.status_code == 200
    me_data = me_resp.json()
    assert me_data["username"] == "testadmin"
    assert me_data["email"] == "admin@example.com"
