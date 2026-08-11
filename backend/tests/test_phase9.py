"""
Phase 9 unit verification tests.
Tests relationship network graph generator, chronological timeline sorting, GeoIP coordinates extraction,
chart metric distributions, and FastAPI visualization router.
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
from services import visualization_service
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


def override_get_db_p9():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


def test_relationship_graph_units():
    db = TestingSessionLocal()
    inv = Investigation(title="Graph Test Case", status="active")
    db.add(inv)
    db.commit()
    db.refresh(inv)

    finding = Finding(investigation_id=inv.id, module="domain", type="domain_scan", data={"target": "example.com"})
    ioc = IOC(value="93.184.216.34", type="ip", source="domain_scan")
    db.add_all([finding, ioc])
    db.commit()

    res = visualization_service.get_relationship_graph(db, inv.id)
    assert res["total_nodes"] >= 3
    assert res["total_links"] >= 2
    types = [n["type"] for n in res["nodes"]]
    assert "investigation" in types
    assert "finding" in types
    assert "ioc" in types
    db.close()


def test_timeline_sorting_units():
    db = TestingSessionLocal()
    inv = Investigation(title="Timeline Test Case", status="active")
    db.add(inv)
    db.commit()
    db.refresh(inv)

    finding = Finding(investigation_id=inv.id, module="ip", type="ip_scan", data={"target": "8.8.8.8"})
    db.add(finding)
    db.commit()

    res = visualization_service.get_timeline(db, inv.id)
    assert res["total_events"] >= 2
    # Verify events have timestamps and sorted order
    ts_list = [e["timestamp"] for e in res["events"] if e["timestamp"]]
    assert ts_list == sorted(ts_list)
    db.close()


def test_geo_map_extraction_units():
    db = TestingSessionLocal()
    inv = Investigation(title="Geo Map Case", status="active")
    db.add(inv)
    db.commit()
    db.refresh(inv)

    finding = Finding(
        investigation_id=inv.id,
        module="ip",
        type="ip_scan",
        data={
            "target": "8.8.8.8",
            "geoip": {
                "country": "United States",
                "country_code": "US",
                "city": "Mountain View",
                "latitude": 37.4056,
                "longitude": -122.0775,
                "isp": "Google LLC"
            }
        }
    )
    db.add(finding)
    db.commit()

    res = visualization_service.get_geo_map(db, inv.id)
    assert res["total_locations"] >= 1
    loc = res["locations"][0]
    assert loc["ip"] == "8.8.8.8"
    assert loc["country_code"] == "US"
    assert loc["latitude"] == 37.4056
    db.close()


def test_chart_metrics_aggregation_units():
    db = TestingSessionLocal()
    inv = Investigation(title="Metrics Case", status="active")
    db.add(inv)
    db.commit()
    db.refresh(inv)

    f1 = Finding(investigation_id=inv.id, module="domain", type="domain_scan", data={})
    f2 = Finding(investigation_id=inv.id, module="ip", type="ip_scan", data={"open_ports": [80, 443]})
    db.add_all([f1, f2])
    db.commit()

    res = visualization_service.get_chart_metrics(db, inv.id)
    assert res["total_findings"] == 2
    assert res["module_distribution"]["domain"] == 1
    assert res["module_distribution"]["ip"] == 1
    assert res["severity_breakdown"]["HIGH"] == 1
    db.close()


def test_visualization_api_workflow():
    app.dependency_overrides[get_db] = override_get_db_p9
    client = TestClient(app)

    # 1. Register User
    reg_resp = client.post(
        "/api/auth/register",
        json={"username": "viz_analyst", "email": "viz@example.com", "password": "SecurePassword123!"},
    )
    assert reg_resp.status_code == 201

    # 2. Login
    login_resp = client.post(
        "/api/auth/login",
        json={"username_or_email": "viz_analyst", "password": "SecurePassword123!"},
    )
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 3. Create Case
    case_resp = client.post(
        "/api/investigations",
        json={"title": "Visualization Case", "description": "Testing Phase 9 endpoints", "tags": ["viz_test"]},
        headers=headers,
    )
    assert case_resp.status_code == 201
    inv_id = case_resp.json()["id"]

    # 4. Test Relationship Graph API
    graph_resp = client.get(f"/api/visualization/relationship-graph/{inv_id}", headers=headers)
    assert graph_resp.status_code == 200
    assert "nodes" in graph_resp.json()

    # 5. Test Timeline API
    time_resp = client.get(f"/api/visualization/timeline/{inv_id}", headers=headers)
    assert time_resp.status_code == 200
    assert "events" in time_resp.json()

    # 6. Test Geo Map API
    geo_resp = client.get(f"/api/visualization/geo-map/{inv_id}", headers=headers)
    assert geo_resp.status_code == 200
    assert "locations" in geo_resp.json()

    # 7. Test Metrics API
    met_resp = client.get(f"/api/visualization/metrics/{inv_id}", headers=headers)
    assert met_resp.status_code == 200
    assert "module_distribution" in met_resp.json()
