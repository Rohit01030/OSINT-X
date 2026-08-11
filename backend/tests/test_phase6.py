"""
Phase 6 unit verification tests.
Tests Email, Username, and File Intelligence modules, including services, API routers, and db storage.
"""
import pytest
import asyncio
from io import BytesIO
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from PIL import Image

from database.session import Base, get_db
from models.finding import Finding
from models.ioc import IOC
from services import email_service, username_service, file_service
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


def override_get_db_p6():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


def generate_mock_image_bytes() -> bytes:
    """Generates a 100x100 Red JPEG image with EXIF metadata in memory."""
    im = Image.new("RGB", (100, 100), color="red")
    exif = im.getexif()
    exif[271] = "BrandMock"  # Make
    exif[272] = "ModelMock"  # Model
    f = BytesIO()
    im.save(f, format="JPEG", exif=exif)
    return f.getvalue()


@pytest.fixture
def mock_dns():
    """Mocks dns.resolver.Resolver.resolve for passive audits."""
    with patch("dns.resolver.Resolver.resolve") as mock_resolve:
        def side_effect(qname, rdtype):
            mock_ans = MagicMock()
            if rdtype == "MX":
                mock_ans.preference = 10
                mock_ans.exchange = "mail.mocktarget.com."
                return [mock_ans]
            elif rdtype == "TXT":
                mock_ans.strings = [b"v=spf1 include:_spf.mocktarget.com ~all"]
                if str(qname).startswith("_dmarc"):
                    mock_ans.strings = [b"v=DMARC1; p=reject; pct=100;"]
                return [mock_ans]
            raise Exception("DNS Query Failed")
        
        mock_resolve.side_effect = side_effect
        yield mock_resolve


@pytest.fixture
def mock_httpx_username():
    """Mocks HTTPX AsyncClient requests for username check."""
    with patch("httpx.AsyncClient.get") as mock_get:
        async def side_effect(url, *args, **kwargs):
            resp = MagicMock()
            if "github.com" in url or "reddit.com" in url:
                resp.status_code = 200
                resp.text = "profile page content"
            else:
                resp.status_code = 404
                resp.text = "not found"
            return resp
        mock_get.side_effect = side_effect
        yield mock_get


def test_email_service_units(mock_dns):
    # Test DNS check logic
    sec = email_service.check_email_security("test@mocktarget.com")
    assert sec["domain"] == "mocktarget.com"
    assert len(sec["mx"]) > 0
    assert sec["spf"] == "v=spf1 include:_spf.mocktarget.com ~all"
    assert sec["dmarc"] == "v=DMARC1; p=reject; pct=100;"

    # Test breach status simulation mode
    breaches = email_service.check_email_breaches("test@example.com")
    assert len(breaches) > 0
    assert breaches[0]["Name"] == "Adobe"

    breaches_empty = email_service.check_email_breaches("safe@example.com")
    assert len(breaches_empty) == 0


def test_username_service_units(mock_httpx_username):
    results = asyncio.run(username_service.check_username_platforms("johndoe"))
    github_res = next(r for r in results if r["platform"] == "GitHub")
    assert github_res["exists"] is True

    pinterest_res = next(r for r in results if r["platform"] == "Pinterest")
    assert pinterest_res["exists"] is False


def test_file_service_units():
    # Test hashing
    dummy = b"OSINT-X-test-payload"
    hashes = file_service.calculate_hashes(dummy)
    assert "md5" in hashes
    assert "sha256" in hashes
    assert hashes["sha256"] == "825acfb0ce96caadf52c01903d3196f9ac307bd2e25bd9a75de9a71e6bdadaf3"

    # Test Pillow metadata extraction
    img_bytes = generate_mock_image_bytes()
    meta = file_service.extract_exif_metadata(img_bytes, "test.jpg")
    assert meta["is_image"] is True
    assert meta["format"] == "JPEG"
    assert meta["width"] == 100
    assert meta["height"] == 100
    assert meta["exif"].get("Make") == "BrandMock"
    assert meta["exif"].get("Model") == "ModelMock"


def test_phase6_api_workflow(mock_dns, mock_httpx_username):
    app.dependency_overrides[get_db] = override_get_db_p6
    client = TestClient(app)

    # 1. Register
    reg_resp = client.post(
        "/api/auth/register",
        json={"username": "intel_analyst", "email": "analyst@example.com", "password": "SecurePassword123!"},
    )
    assert reg_resp.status_code == 201

    # 2. Login
    login_resp = client.post(
        "/api/auth/login",
        json={"username_or_email": "intel_analyst", "password": "SecurePassword123!"},
    )
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 3. Create Case
    case_resp = client.post(
        "/api/investigations",
        json={"title": "Phase 6 Case", "description": "Testing email, username, file scans", "tags": ["phase6"]},
        headers=headers,
    )
    assert case_resp.status_code == 201
    inv_id = case_resp.json()["id"]

    # 4. Test Email Analyze Endpoint
    email_resp = client.post(
        "/api/email/analyze",
        json={"investigation_id": inv_id, "target": "test@mocktarget.com"},
        headers=headers,
    )
    assert email_resp.status_code == 200
    e_data = email_resp.json()
    assert e_data["target"] == "test@mocktarget.com"
    assert e_data["email_security"]["spf"] is not None

    # 5. Test Username Analyze Endpoint
    user_resp = client.post(
        "/api/username/analyze",
        json={"investigation_id": inv_id, "target": "johndoe"},
        headers=headers,
    )
    assert user_resp.status_code == 200
    u_data = user_resp.json()
    assert u_data["target"] == "johndoe"
    assert u_data["summary"]["total_found"] > 0

    # 6. Test File Analyze Endpoint
    img_data = generate_mock_image_bytes()
    file_payload = {"investigation_id": (None, inv_id)}
    files = {"file": ("test.jpg", img_data, "image/jpeg")}
    
    file_resp = client.post(
        "/api/file/analyze",
        data=file_payload,
        files=files,
        headers=headers,
    )
    assert file_resp.status_code == 200
    f_data = file_resp.json()
    assert f_data["target"] == "test.jpg"
    assert f_data["image_metadata"]["is_image"] is True
    assert f_data["image_metadata"]["exif"]["Make"] == "BrandMock"

    # Verify DB state
    db = TestingSessionLocal()
    findings = db.query(Finding).filter(Finding.investigation_id == inv_id).all()
    assert len(findings) == 3  # Email, Username, File scans
    modules = [f.module for f in findings]
    assert "email" in modules
    assert "username" in modules
    assert "file" in modules

    # Verify IOC table entries
    iocs = db.query(IOC).all()
    ioc_values = [i.value for i in iocs]
    # Email IOC
    assert "test@mocktarget.com" in ioc_values
    # Domain IOC
    assert "mocktarget.com" in ioc_values
    # Username IOC
    assert "johndoe" in ioc_values
    # Hash IOC (sha256 of dummy img_data)
    import hashlib
    img_hash = hashlib.sha256(img_data).hexdigest()
    assert img_hash in ioc_values

    db.close()
